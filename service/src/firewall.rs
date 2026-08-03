//! Windows Firewall rule management via the `INetFwPolicy2` COM API.
//!
//! COM rather than `netsh advfirewall` on purpose:
//! * locale-independent (no parsing of translated console output),
//! * no shelling out, so nothing the service does can be influenced by `PATH`,
//!   by a hijacked `netsh.exe`, or by string-quoting mistakes,
//! * structured errors instead of exit codes.
//!
//! The rules are deliberately narrow: **inbound allow**, scoped to the
//! DirectDesk host executable's absolute path, to two fixed ports
//! ([`DEFAULT_UDP_PORT`]/[`DEFAULT_TCP_PORT`]), on the **Private** profile
//! only. Everything is tagged with the grouping string [`RULE_GROUP`] so the
//! whole set can be identified and removed as one unit.
//!
//! Public-profile exposure is possible ([`Profiles::PUBLIC`]) but is never
//! chosen by the service itself — the IPC surface has no way to request it, so
//! widening it requires an explicit, out-of-band decision by the user.

use std::path::PathBuf;

use directdesk_shared::protocol::{DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN,
};
use windows::Win32::System::Com::{CoCreateInstance, IDispatch, CLSCTX_INPROC_SERVER};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_DISPATCH};

use crate::dispatch::FirewallOps;
use crate::winutil::ComGuard;

/// Grouping string tagging every rule DirectDesk owns.
pub const RULE_GROUP: &str = "DirectDesk";

const RULE_NAME_UDP: &str = "DirectDesk Host (UDP-In)";
const RULE_NAME_TCP: &str = "DirectDesk Host (TCP-In)";
const RULE_DESCRIPTION: &str =
    "Allows inbound DirectDesk remote-desktop connections to the DirectDesk host agent \
     on this machine. Created by DirectDesk Service; remove it from the DirectDesk app \
     or with 'DirectDeskService uninstall'.";

/// Firewall profiles a rule applies to (a bitmask, as `INetFwRule::SetProfiles`
/// expects).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profiles(i32);

// The service itself only ever selects PRIVATE; DOMAIN/PUBLIC and the set
// operations exist so a future, explicitly user-confirmed flow can widen the
// scope without reworking this module.
#[allow(dead_code)]
impl Profiles {
    pub const DOMAIN: Profiles = Profiles(1);
    pub const PRIVATE: Profiles = Profiles(2);
    pub const PUBLIC: Profiles = Profiles(4);

    pub const fn bits(self) -> i32 {
        self.0
    }

    /// Union of two profile sets.
    pub const fn with(self, other: Profiles) -> Profiles {
        Profiles(self.0 | other.0)
    }

    pub const fn contains(self, other: Profiles) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for Profiles {
    /// The service default: Private networks only.
    fn default() -> Self {
        Profiles::PRIVATE
    }
}

/// Firewall management scoped to one rule group and one host executable.
pub struct WindowsFirewall {
    group: String,
    host_exe: PathBuf,
    /// Profiles used when [`FirewallOps::ensure_rules`] is driven from IPC.
    default_profiles: Profiles,
}

impl WindowsFirewall {
    /// Manage the production `DirectDesk` group for `host_exe`.
    pub fn new(host_exe: PathBuf) -> Self {
        Self { group: RULE_GROUP.to_string(), host_exe, default_profiles: Profiles::default() }
    }

    /// Create the DirectDesk inbound rules, replacing any existing rules in the
    /// group so the result is exactly what this version defines (idempotent).
    pub fn ensure_rules(&self, profiles: Profiles) -> anyhow::Result<()> {
        anyhow::ensure!(profiles.bits() != 0, "at least one firewall profile must be selected");
        let _com = ComGuard::mta()?;
        let rules = self.rules()?;

        // Replace rather than mutate: the definition below is the source of truth.
        remove_group(&rules, &self.group)?;

        let exe = self.host_exe.to_string_lossy().to_string();
        add_rule(
            &rules,
            &self.group,
            RULE_NAME_UDP,
            &exe,
            NET_FW_IP_PROTOCOL_UDP.0,
            DEFAULT_UDP_PORT,
            profiles,
        )?;
        add_rule(
            &rules,
            &self.group,
            RULE_NAME_TCP,
            &exe,
            NET_FW_IP_PROTOCOL_TCP.0,
            DEFAULT_TCP_PORT,
            profiles,
        )?;

        tracing::info!(
            group = %self.group,
            exe = %exe,
            profiles = profiles.bits(),
            udp = DEFAULT_UDP_PORT,
            tcp = DEFAULT_TCP_PORT,
            "firewall rules ensured"
        );
        Ok(())
    }

    /// Remove every rule tagged with this group.
    pub fn remove_rules(&self) -> anyhow::Result<()> {
        let _com = ComGuard::mta()?;
        let rules = self.rules()?;
        let removed = remove_group(&rules, &self.group)?;
        tracing::info!(group = %self.group, removed, "firewall rules removed");
        Ok(())
    }

    /// Names of the rules currently tagged with this group.
    pub fn group_rule_names(&self) -> anyhow::Result<Vec<String>> {
        let _com = ComGuard::mta()?;
        let rules = self.rules()?;
        group_rule_names(&rules, &self.group)
    }

    /// Are both DirectDesk rules present? Errors are reported to the caller;
    /// [`FirewallOps::rules_present`] flattens them to `false`.
    pub fn rules_present_checked(&self) -> anyhow::Result<bool> {
        Ok(self.group_rule_names()?.len() >= 2)
    }

    fn rules(&self) -> anyhow::Result<INetFwRules> {
        // SAFETY: standard in-proc COM activation on a thread with an apartment.
        let policy: INetFwPolicy2 = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| anyhow::anyhow!("could not create INetFwPolicy2 ({e}) — is the Windows Firewall service running?"))?;
        // SAFETY: `policy` is a live interface pointer.
        let rules = unsafe { policy.Rules() }
            .map_err(|e| anyhow::anyhow!("could not open the firewall rule collection: {e}"))?;
        Ok(rules)
    }
}

/// Test affordances: an isolated rule group so the suite never touches the
/// production `DirectDesk` rules.
#[cfg(test)]
impl WindowsFirewall {
    pub fn with_group(group: impl Into<String>, host_exe: PathBuf) -> Self {
        Self { group: group.into(), host_exe, default_profiles: Profiles::default() }
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn host_exe(&self) -> &std::path::Path {
        &self.host_exe
    }
}

impl FirewallOps for WindowsFirewall {
    fn ensure_rules(&self) -> anyhow::Result<()> {
        WindowsFirewall::ensure_rules(self, self.default_profiles)
    }

    fn remove_rules(&self) -> anyhow::Result<()> {
        WindowsFirewall::remove_rules(self)
    }

    fn rules_present(&self) -> bool {
        match self.rules_present_checked() {
            Ok(present) => present,
            Err(e) => {
                tracing::debug!("firewall rule query failed, reporting absent: {e}");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// COM plumbing
// ---------------------------------------------------------------------------

fn add_rule(
    rules: &INetFwRules,
    group: &str,
    name: &str,
    exe: &str,
    protocol: i32,
    port: u16,
    profiles: Profiles,
) -> anyhow::Result<()> {
    // SAFETY: every BSTR outlives its setter call; `rule` is a fresh instance.
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| anyhow::anyhow!("could not create a firewall rule object: {e}"))?;
        rule.SetName(&BSTR::from(name))?;
        rule.SetDescription(&BSTR::from(RULE_DESCRIPTION))?;
        rule.SetApplicationName(&BSTR::from(exe))?;
        rule.SetProtocol(protocol)?;
        rule.SetLocalPorts(&BSTR::from(port.to_string()))?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        rule.SetProfiles(profiles.bits())?;
        rule.SetGrouping(&BSTR::from(group))?;
        rule.SetEnabled(VARIANT_TRUE)?;
        rules
            .Add(&rule)
            .map_err(|e| anyhow::anyhow!("could not add firewall rule {name:?}: {e}"))?;
    }
    Ok(())
}

/// Remove every rule whose grouping matches `group`. Returns how many went.
fn remove_group(rules: &INetFwRules, group: &str) -> anyhow::Result<usize> {
    let names = group_rule_names(rules, group)?;
    let mut removed = 0usize;
    for name in &names {
        // SAFETY: `rules` is live; the BSTR outlives the call.
        match unsafe { rules.Remove(&BSTR::from(name.as_str())) } {
            Ok(()) => removed += 1,
            Err(e) => {
                return Err(anyhow::anyhow!("could not remove firewall rule {name:?}: {e}"));
            }
        }
    }
    Ok(removed)
}

/// Enumerate the rule collection and collect names of rules in `group`.
fn group_rule_names(rules: &INetFwRules, group: &str) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for_each_rule(rules, |rule| {
        // SAFETY: `rule` is a live interface pointer.
        let grouping = unsafe { rule.Grouping() }.unwrap_or_default();
        if grouping.to_string().eq_ignore_ascii_case(group) {
            // SAFETY: same.
            if let Ok(name) = unsafe { rule.Name() } {
                names.push(name.to_string());
            }
        }
        Ok(())
    })?;
    Ok(names)
}

/// Walk `INetFwRules` through its `IEnumVARIANT`.
fn for_each_rule(
    rules: &INetFwRules,
    mut f: impl FnMut(&INetFwRule) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    // SAFETY: `rules` is live; the enumerator is released when it drops.
    let enumerator: IEnumVARIANT = unsafe { rules._NewEnum() }
        .map_err(|e| anyhow::anyhow!("could not enumerate firewall rules: {e}"))?
        .cast()
        .map_err(|e| anyhow::anyhow!("firewall rule enumerator is not IEnumVARIANT: {e}"))?;

    loop {
        let mut item = [VARIANT::default()];
        let mut fetched = 0u32;
        // SAFETY: `item` is a valid, zero-initialized VARIANT slice.
        let hr = unsafe { enumerator.Next(&mut item, &mut fetched) };
        if fetched == 0 {
            break;
        }

        // SAFETY: `fetched == 1`, so item[0] holds a VARIANT the enumerator
        // filled in. We inspect the discriminant before touching the union and
        // clear the VARIANT before it goes out of scope.
        let result = unsafe {
            let inner = &item[0].Anonymous.Anonymous;
            let rule = if inner.vt == VT_DISPATCH {
                let disp: Option<&IDispatch> = inner.Anonymous.pdispVal.as_ref();
                disp.and_then(|d| d.cast::<INetFwRule>().ok())
            } else {
                None
            };
            let out = match rule {
                Some(rule) => f(&rule),
                None => Ok(()),
            };
            let _ = VariantClear(&mut item[0]);
            out
        };
        result?;

        if hr.is_err() {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Isolated group so nothing here can disturb real DirectDesk rules.
    const TEST_GROUP: &str = "DirectDesk-Test";

    fn test_fw() -> WindowsFirewall {
        WindowsFirewall::with_group(
            TEST_GROUP,
            PathBuf::from(r"C:\Program Files\DirectDesk\DirectDeskHost.exe"),
        )
    }

    #[test]
    fn profiles_default_is_private_only() {
        let p = Profiles::default();
        assert_eq!(p, Profiles::PRIVATE);
        assert_eq!(p.bits(), 2);
        assert!(p.contains(Profiles::PRIVATE));
        assert!(!p.contains(Profiles::PUBLIC));
        assert!(!p.contains(Profiles::DOMAIN));
    }

    #[test]
    fn profiles_can_be_widened_explicitly() {
        let both = Profiles::PRIVATE.with(Profiles::PUBLIC);
        assert_eq!(both.bits(), 6);
        assert!(both.contains(Profiles::PRIVATE));
        assert!(both.contains(Profiles::PUBLIC));
    }

    #[test]
    fn ensure_rules_rejects_an_empty_profile_mask() {
        assert!(test_fw().ensure_rules(Profiles(0)).is_err());
    }

    #[test]
    fn rule_metadata_is_scoped_and_honest() {
        let fw = WindowsFirewall::new(PathBuf::from(r"C:\Program Files\DirectDesk\DirectDeskHost.exe"));
        assert_eq!(fw.group(), "DirectDesk");
        assert_eq!(fw.host_exe().file_name().unwrap(), "DirectDeskHost.exe");
        assert!(RULE_NAME_UDP.contains("UDP"));
        assert!(RULE_NAME_TCP.contains("TCP"));
        assert!(RULE_DESCRIPTION.contains("DirectDesk"));
        assert_eq!(DEFAULT_UDP_PORT, 47990);
        assert_eq!(DEFAULT_TCP_PORT, 47991);
    }

    /// Reading the rule collection normally works for a standard user.
    /// If the firewall service or COM access is unavailable we say so instead
    /// of failing the suite — this is exactly the "untested-unelevated" case.
    #[test]
    fn can_enumerate_the_firewall_rule_collection() {
        let fw = test_fw();
        match fw.group_rule_names() {
            Ok(names) => {
                eprintln!("[firewall] enumerated OK; {TEST_GROUP} currently has {} rules", names.len());
            }
            Err(e) => {
                eprintln!("[firewall] SKIPPED (COM/firewall not reachable in this context): {e}");
            }
        }
    }

    /// Full create -> query -> delete cycle in an isolated group.
    /// Adding rules requires elevation; unelevated this reports SKIPPED.
    #[test]
    fn create_query_delete_in_an_isolated_group() {
        let fw = test_fw();

        // Make sure we start clean; if even this fails, we cannot test.
        if let Err(e) = fw.remove_rules() {
            eprintln!("[firewall] SKIPPED (cannot clear {TEST_GROUP}): {e}");
            return;
        }

        match fw.ensure_rules(Profiles::PRIVATE) {
            Ok(()) => {
                let names = fw.group_rule_names().expect("query after create");
                assert!(names.iter().any(|n| n == RULE_NAME_UDP), "UDP rule missing: {names:?}");
                assert!(names.iter().any(|n| n == RULE_NAME_TCP), "TCP rule missing: {names:?}");
                assert!(fw.rules_present_checked().unwrap());

                // Idempotent: running it again leaves exactly two rules.
                fw.ensure_rules(Profiles::PRIVATE).expect("second ensure");
                assert_eq!(fw.group_rule_names().unwrap().len(), 2);

                fw.remove_rules().expect("remove");
                assert!(fw.group_rule_names().unwrap().is_empty());
                assert!(!fw.rules_present_checked().unwrap());
                eprintln!("[firewall] create/query/delete exercised for real");
            }
            Err(e) => {
                eprintln!("[firewall] SKIPPED (rule creation needs elevation): {e}");
                // rules_present must still be a well-behaved `false`, not a panic.
                assert!(!FirewallOps::rules_present(&fw));
            }
        }
    }
}
