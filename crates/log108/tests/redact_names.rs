use log108::is_sensitive_field;

#[test]
fn secret_bearing_names_missed_on_721aa0c_are_masked() {
    for name in [
        "pincode",
        "passcode",
        "userPasscode",
        "acct",
        "acct_id",
        "accountNo",
        "account_no",
        "accountno",
        "card_no",
        "cardNo",
        "cardno",
        "pairing_code",
        "pairingCode",
    ] {
        assert!(is_sensitive_field(name), "{name} must be masked");
    }
}

#[test]
fn names_that_must_stay_visible_still_do() {
    for name in [
        "sessions",
        "session_count",
        "board",
        "latency_ms",
        "event",
        "target",
        "accounts_total_count",
    ] {
        assert!(!is_sensitive_field(name), "{name} must stay visible");
    }
}
