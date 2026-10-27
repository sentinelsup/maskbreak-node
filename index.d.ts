export interface EvaluateDetails {
    ip: string;
    cc: string;
    vpn: boolean;
    proxied: boolean;
    dch: boolean;
    anon: boolean;
    crawler?: boolean;
    service?: string;
    /** Present (true) only when the Tor exit list matched; read network.tor instead. */
    tor?: boolean;
}

export interface DeviceIntel {
    visitorId: string | null;
    browserTampering: boolean;
    botDetected: boolean;
    vpnDetected: boolean;
    proxyDetected: boolean;
    torDetected: boolean;
    ipBlocklisted: boolean;
    incognito: boolean;
    virtualMachine: boolean;
    emulator: boolean;
    tamperingScore?: number;
    /** Legacy name of device.privacy_mode. */
    privacySettings?: boolean;
    /** Legacy name of device.high_activity. */
    highActivity?: boolean;
}

export interface NetworkSignals {
    vpn: boolean;
    /** Also true for Apple's iCloud Private Relay (see privacy_relay). */
    proxy: boolean;
    /** True when the proxy is Apple's iCloud Private Relay (since 2026-10-10;
     *  sent on every evaluation). On its own it is `review`, never `block`, with
     *  the reason `privacy_relay` instead of `proxy_detected`. */
    privacy_relay?: boolean;
    datacenter: boolean;
    anonymous: boolean;
    tor: boolean;
    residential: boolean;
    /** VPN/proxy service name when known; otherwise null. */
    service: string | null;
    /** False for a partial network reading (higher chance of a wrong answer)
     *  or when there was no reading. Informational; never changes `decision`. */
    complete?: boolean;
    /** True when a token arrived but the network check could not measure the
     *  visitor (blocked or stripped measurement). Informational. */
    sdk_blocked?: boolean;
}

export interface EvidenceFreshness {
    /** Seconds between the network reading and this call */
    network_age_s?: number;
    /** Seconds between the device event and this call */
    device_age_s?: number;
    /** True when the device event was marked as a replay of an earlier one */
    device_replayed?: boolean;
}

/** A boolean device field backed by an explicit result (device.checked_signals). */
export type DeviceCheckedSignal =
    | 'antidetect' | 'automation' | 'emulator' | 'virtual_machine' | 'incognito'
    | 'privacy_mode' | 'ip_blocklisted' | 'high_activity';

/** The opt-in browser-consistency beta (raw HTTP `browserEvidence`). Browser-reported,
 *  forgeable observations, not hardware attestation. */
export interface BrowserConsistencyResult {
    status: 'consistent' | 'inconsistent' | 'inconclusive' | 'disabled' | 'invalid'
        | 'expired_or_used' | 'not_saved' | 'unavailable';
    experimental: true;
    source?: 'browser_reported';
    /** True when a finding raised this answer from allow to review (never to block). */
    affects_decision?: boolean;
    findings?: Array<'browser_context' | 'gpu_calculation' | 'gpu_os_plausibility' | 'gpu_backend_os' | 'gpu_vendor_agreement'>;
    checks?: Array<{
        id: 'browser_context' | 'graphics_paths' | 'gpu_calculation' | 'gpu_os_plausibility' | 'gpu_backend_os' | 'gpu_vendor_agreement';
        status: 'consistent' | 'mismatch' | 'different' | 'unavailable';
        fields?: Array<'browser' | 'os'>;
    }>;
    /** 8-character hashes of three canvases drawn in the browser (never an image). */
    measurements?: {
        canvas_default?: string | null;
        canvas_cpu?: string | null;
        canvas_hardware?: string | null;
        canvas_acceleration?: 'accelerated' | 'software' | 'unavailable';
    };
    hardware_profiles?: number;
    machine_profiles?: number;
}

export interface DeviceSignals {
    /** True when browser tampering and bot checks returned valid results. Informational. */
    complete?: boolean;
    /** Boolean fields below backed by an explicit result. A field missing here was not
     *  checked, even when its compatibility boolean is false. */
    checked_signals?: DeviceCheckedSignal[];
    antidetect: boolean;
    automation: boolean;
    emulator: boolean;
    virtual_machine: boolean;
    incognito: boolean;
    privacy_mode: boolean;
    ip_blocklisted: boolean;
    visitor_id: string | null;
    tampering_score: number;
    high_activity: boolean;
    /** Retained sightings of this device across Maskbreak, not scoped to your account.
     *  Present when identified; records are pruned after 90 days of inactivity. */
    times_seen?: number;
    /** ISO 8601 first sighting in the retained device record, not necessarily its lifetime first visit. */
    first_seen?: string;
    returning?: boolean;
    /** Distinct accountIds linked to this device for your customer account only.
     *  Requires accountId and an identified device; links are pruned after 90 days of inactivity. */
    linked_accounts?: number;
    multi_account?: boolean;
    /** Customer-only distinct verified events in the last 90 days. Test keys excluded. */
    customer_history?: {
        device_key: string; window_days: 90; visits: number; returning: boolean;
        first_seen: string; last_seen: string; accounts: number;
    };
    /** Optional HTTP-only beta. Resemblance is not identity or a fraud score. */
    gpu_evidence?: {
        experimental: true;
        status: 'recorded' | 'disabled' | 'invalid' | 'expired_or_used' | 'not_saved' | 'unavailable';
        nearest?: {device_key: string; distance: number} | null;
    };
    /** Opt-in browser-consistency beta (raw HTTP `browserEvidence`). */
    browser_consistency?: BrowserConsistencyResult;
}

export type ReasonCode =
    | 'vpn_detected' | 'proxy_detected' | 'privacy_relay' | 'datacenter_asn' | 'tor_exit_node'
    | 'anonymous_network' | 'antidetect_browser' | 'automation_detected'
    | 'emulator_detected' | 'virtual_machine' | 'ip_blocklisted' | 'private_browsing'
    | 'high_activity_device' | 'multi_account_device' | 'disposable_email' | 'timezone_mismatch'
    | 'account_new_device' | 'account_many_devices' | 'device_many_accounts' | 'ip_many_accounts'
    /** Opt-in browser-consistency beta (since 17 October 2026): each raises allow to review, never to block. */
    | 'gpu_inconsistent' | 'antidetect_randomization' | 'antidetect_profile_burst'
    /** Login protection (since 23 October 2026): a takeover score of 80 or more; raises allow to review, never to block. */
    | 'account_takeover_risk'
    /** Email and phone intelligence (since 23 October 2026): a score of 80 or more; each raises allow to review, never to block. */
    | 'email_high_risk' | 'phone_high_risk';

/** The account network (since 18 October 2026): present when you send
 *  accountId with a live key. Scoped to your account only; shared exits
 *  (VPN, proxy, datacenter, Tor, Apple's relay, mobile carriers) never link. */
export interface AccountNetwork {
    /** This accountId was checked before, within 90 days. */
    seen_before: boolean;
    first_seen: string | null;
    /** Checked before on another device, never on this one (account_new_device). Null without device evidence. */
    new_device: boolean | null;
    /** Devices this account used in 24 h; 3+ adds account_many_devices. */
    devices_24h: number;
    devices_90d: number;
    /** Your accounts on this device in 24 h, this one included; 3+ adds
     *  device_many_accounts and raises allow to review. Null without device evidence. */
    device_accounts_24h: number | null;
    /** Your accounts from this address in 24 h; 3+ adds ip_many_accounts.
     *  Null when no address was measured or it is a shared exit. */
    ip_accounts_24h: number | null;
    /** Your other accounts sharing a device or an address within 90 days. */
    connected_accounts: number;
    connected_by_device: number;
}

/** low below 50, medium 50 to 79, high 80 and up. */
export type RiskBand = 'low' | 'medium' | 'high';

/** Why email or phone intelligence gave no score (checked: false). invalid, busy and
 *  unavailable use none of the day's email-and-phone checks; test = a test key, a test
 *  token or the sandbox, which never reach the provider. */
export type ContactCheckWhy = 'not_enabled' | 'not_available' | 'quota' | 'invalid' | 'test' | 'busy' | 'unavailable';

export interface EmailSignals {
    /** True when the address uses a disposable/burner domain (Maskbreak's feed; with
     *  email and phone intelligence on, also when the provider says so). Sent for an
     *  address of 3 to 254 characters with an @. */
    disposable: boolean;
    /** Email and phone intelligence (since 23 October 2026): on every email block;
     *  true when the provider scored the address. */
    checked?: boolean;
    /** 0–100, higher is riskier. Present when checked is true; null when the provider
     *  answered without a score. 80 or more adds email_high_risk and raises allow to
     *  review, never to block. */
    score?: number | null;
    risk?: RiskBand | null;
    /** What the score noticed, by name (disposable, free_provider, no_online_accounts,
     *  young_domain, undeliverable, breaches, fraud_reports, ...; the list can grow). */
    signals?: string[];
    online_accounts?: number | null;
    breaches?: number | null;
    deliverable?: boolean | null;
    free_provider?: boolean | null;
    /** When the domain was registered, as a date (YYYY-MM-DD). */
    domain_created?: string | null;
    /** Present when checked is false. */
    why?: ContactCheckWhy;
}

/** Email and phone intelligence (since 23 October 2026): present when you sent phone. */
export interface PhoneIntelligence {
    /** True when the provider scored the number. */
    checked: boolean;
    /** 0–100, higher is riskier. Present when checked is true; null when the provider
     *  answered without a score. 80 or more adds phone_high_risk and raises allow to
     *  review, never to block. */
    score?: number | null;
    risk?: RiskBand | null;
    /** What the score noticed, by name (invalid, disposable, virtual, no_online_accounts,
     *  fraud_reports, ...; the list can grow). */
    signals?: string[];
    valid?: boolean | null;
    /** mobile, fixed_line, fixed_line_or_mobile, voip, toll_free, premium_rate, ... */
    line_type?: string | null;
    carrier?: string | null;
    /** 2-letter country code of the number. */
    country?: string | null;
    /** A temporary or virtual number. */
    disposable?: boolean | null;
    online_accounts?: number | null;
    /** Present when checked is false. */
    why?: ContactCheckWhy;
}

/** Why login protection gave no answer: not_enabled (switched off in Settings),
 *  not_available, no_account_id, test (test keys, test tokens and the sandbox never
 *  reach the provider), busy or unavailable (the rest of the answer is unaffected). */
export type LoginProtectionWhy = 'not_enabled' | 'not_available' | 'no_account_id' | 'test' | 'busy' | 'unavailable';

/** Login protection (since 23 October 2026): present when you sent event 'login'. */
export interface AccountTakeover {
    /** True when the login was scored. */
    checked: boolean;
    /** 0–100, higher is riskier. 80 or more adds account_takeover_risk and raises allow
     *  to review, never to block. Present when checked is true. */
    score?: number;
    risk?: RiskBand;
    /** What the score noticed, by name (new_location, new_device_id, new_ip_address, ...;
     *  the list can grow). */
    signals?: string[];
    /** Present when checked is false. */
    why?: LoginProtectionWhy;
}

/** Login protection (since 23 October 2026): present when you sent an account event
 *  (any event but 'login'). No score comes back for these. */
export interface AccountEvent {
    event: AccountEventName;
    /** True when login protection took the event. */
    recorded: boolean;
    /** Present when recorded is false. */
    why?: LoginProtectionWhy;
}

/** Present when a recognised tz was sent and the address's country is known. */
export interface TimezoneSignal {
    /** The IANA zone that was sent, echoed back. */
    reported: string;
    /** The country that zone belongs to. */
    country: string;
    /** True when the zone's country equals the address's country. */
    matches_ip: boolean;
    /** False on a VPN, proxy, Tor or datacenter exit, where a mismatch is expected and
     *  nothing is raised: read matches_ip as information then. */
    checked: boolean;
}

export interface EvaluateResult {
    /** "allow" | "review" | "block" — route on this */
    decision: 'allow' | 'review' | 'block';
    /** 0–100 weighted risk score */
    risk_score: number;
    /** Legacy convenience flag: true when VPN, proxy, Tor, antidetect, automation,
     *  emulator or virtual machine fired. A datacenter or anonymous network alone does
     *  not set it, and email, timezone, rules and pins never change it — route on
     *  `decision` instead. */
    isSuspicious: boolean;
    ip: string | null;
    country: string | null;
    network: NetworkSignals;
    /** Present only when fingerprintEventId was supplied */
    device?: DeviceSignals;
    /** Present when accountId was supplied with a live key (since 18 October 2026) */
    account?: AccountNetwork;
    /** Machine-readable reason codes for the verdict */
    reasons: ReasonCode[];
    evaluated_in_ms: number;
    /** Present when the optional `email` input was supplied */
    email?: EmailSignals;
    /** Present when you sent `phone` (email and phone intelligence, since 23 October 2026) */
    phone?: PhoneIntelligence;
    /** Present when you sent event 'login' (login protection, since 23 October 2026) */
    account_takeover?: AccountTakeover;
    /** Present when you sent another account event (login protection, since 23 October 2026) */
    account_event?: AccountEvent;
    /** Present when you sent a recognised `tz` and the address's country is known */
    timezone?: TimezoneSignal;
    /** Present only when your own rules/exceptions changed `decision`:
     *  the engine's own risk-score verdict */
    engine_decision?: 'allow' | 'review' | 'block';
    /** Who authored the final decision when it was not the engine */
    decision_source?: 'rules' | 'exception';
    /** Signals that triggered a custom rule (decision_source === 'rules') */
    rule_matched?: string[];
    /** Matched per-IP/visitor pins (decision_source === 'exception') */
    exception_matched?: string[];
    /** Present on test-token / sk_test_ key responses. Test-key checks count toward
     *  the monthly allowance; the fixed test_* tokens never count. */
    test?: boolean;
    /** Whether the device layer was usable: "ok" (device present),
     *  "unavailable" (an event id was sent but did not resolve) or
     *  "not_sent". Hold sensitive actions when it is not "ok". */
    device_evidence?: 'ok' | 'unavailable' | 'not_sent';
    /** How fresh the evidence was; only known fields are present */
    evidence?: EvidenceFreshness;
    /** Present and true when the network layer was unavailable (no token, or one that
     *  could not be read): the decision then says nothing about the visitor's network */
    degraded?: boolean;
    /** True when the public sk_test_sandbox key answered */
    sandbox?: boolean;
    /** True on GET /v1/evaluate/sample answers */
    sample?: boolean;
    /** Legacy fields (kept for backwards compatibility) */
    status: string;
    details: EvaluateDetails;
    deviceIntel?: DeviceIntel | null;
}

export interface LookupSignals {
    vpn: boolean;
    /** Proxy detected (legacy field spelling) */
    proxied: boolean;
    tor: boolean;
    /** Datacenter hosting (legacy field spelling) */
    dch: boolean;
    /** Anonymizing behaviors observed */
    anon: boolean;
}

export interface LookupNetwork {
    asn: number | null;
    org: string | null;
    country: string | null;
    city: string | null;
    /** Cloud provider name, present on a provider-range hit */
    cloud?: string;
}

export interface LookupResponse {
    ip: string;
    /** Whether our reputation feeds hold data for this IP.
     *  false does NOT assert the IP is clean. */
    known: boolean;
    verdict: 'allow' | 'review' | 'block';
    /** 0–100 */
    risk_score: number;
    /** Null when known is false */
    signals: LookupSignals | null;
    network: LookupNetwork | null;
    latency_ms: number;
    /** Present only when an exception pin changed `verdict` */
    engine_verdict?: 'allow' | 'review' | 'block';
    verdict_source?: 'exception';
    exception_matched?: string[];
    /** Present when the call used the per-account sk_test_ key */
    test?: boolean;
}

export interface SentinelOptions {
    /** Your Sentinel API key (starts with sk_live_). Get one free at https://maskbreak.com/signup
     *  Omitted: read from the MASKBREAK_API_KEY env var (older SENTINEL_KEY / SENTINEL_API_KEY still work). */
    apiKey?: string;
    /** Override the API base URL (default: https://maskbreak.com) */
    endpoint?: string;
    /** Per-request timeout in ms (default: 5000) */
    timeoutMs?: number;
    /** Let shouldBlock() treat test, sandbox and sample answers as a normal
     *  decision (since 0.4.0 it returns true for them). Only for your own
     *  test runs: the fixed test tokens are public, so a visitor can send one. */
    allowTestResults?: boolean;
    /** False turns off the one-time console warning for a check sent without
     *  fingerprintEventId (since 0.5.0; on by default). */
    warnMissingBrowserPart?: boolean;
}

/** The `event` values (login protection, since 23 October 2026). */
export type EvaluateEvent = 'login' | 'signup' | 'password_change' | 'verification' | 'logout' | 'account_change';
/** Every event but 'login': reported to login protection, no score comes back. */
export type AccountEventName = 'signup' | 'password_change' | 'verification' | 'logout' | 'account_change';
/** The account events evaluate() sends without the network token (since 0.5.0). */
export type TokenlessEvent = 'password_change' | 'verification' | 'logout' | 'account_change';

/** Every field but `token` is optional and sent only when given (not undefined, null
 *  or ''). A value the API would ignore or misread (an unknown event, a non-boolean
 *  loginSucceeded, ...) throws a SentinelError before anything is sent. */
export interface EvaluateInput {
    /** Client-side Sentinel token from the frontend SDK */
    token: string;
    /** Optional device event id for device-layer signals. Without it the check has no
     *  browser part, and the SDK warns once (see warnMissingBrowserPart). */
    fingerprintEventId?: string;
    /** Optional account/user id (your own internal ID, never an email) — enables
     *  multi-accounting detection (device.linked_accounts / device.multi_account)
     *  and the `account` object. Login protection needs it with `event`. */
    accountId?: string | number;
    /** Optional signup email — adds `email.disposable` to the response
     *  (burner domains escalate allow → review). With email and phone intelligence
     *  on, also `checked`, `score`, `risk` and `signals`. Never stored or logged. */
    email?: string;
    /** The visitor's IANA time zone: `tz` from Sentinel.collect(), or the form's
     *  sentinel_tz field (since 0.5.0). Adds `timezone`; a country that disagrees with
     *  an ordinary-looking address adds timezone_mismatch (allow → review). */
    tz?: string;
    /** The visitor's phone number in international format (+ or 00 and the country
     *  code). With email and phone intelligence on it adds the `phone` object with a
     *  score (since 0.5.0). Never stored or logged. */
    phone?: string;
    /** Login protection (since 0.5.0): 'login' adds `account_takeover` with a score; the
     *  other events add `account_event`. Needs `accountId`. Read case-insensitively. */
    event?: EvaluateEvent;
    /** With event 'login': whether the password (or other credential) was right. Send
     *  failed attempts too. */
    loginSucceeded?: boolean;
    /** With event 'password_change' or 'verification': whether it succeeded (absent
     *  means pending). */
    succeeded?: boolean;
    /** With an event: your own session ID, at most 256 characters. Only a keyed hash of
     *  it leaves Maskbreak. */
    sessionId?: string | number;
    /** With an event: the visitor's User-Agent header as your server received it. */
    userAgent?: string;
    /** With an event: the visitor's IP address as your server saw it; used only when
     *  the network token gave no address, and never changes the network verdict. */
    ip?: string;
    /** With event 'password_change': user (the person chose to), forgot (a
     *  forgotten-password flow) or forced (a reset you required). */
    reason?: 'user' | 'forgot' | 'forced';
    /** With event 'verification': how the person was verified. */
    verificationType?: 'email' | 'sms' | 'phone_call' | 'app' | 'push' | 'security_key' | 'captcha';
    /** With event 'verification': which action the verification belonged to. */
    verifiedEvent?: 'login' | 'signup' | 'password_change' | 'account_change';
}

/** An account event your server reports on its own (since 0.5.0): password_change,
 *  verification, logout and account_change may go without the network token. A
 *  login or a signup is a visit and needs the token (EvaluateInput). Without a token
 *  the answer is degraded: its decision says nothing about the visitor's network. */
export interface AccountEventInput extends Omit<EvaluateInput, 'token' | 'event'> {
    token?: string | null;
    event: TokenlessEvent;
}

/** What the latest check showed (GET /v1/setup): waiting (no check in the last 7 days, and none complete before), complete
 *  (both parts, live key), missing_network (no network token), network_unavailable
 *  (a token that could not be read), missing_device (no browser event id),
 *  device_unavailable (a browser event that could not be verified), test_mode (a test
 *  token, or the test key without both parts), test_complete (the test key with both
 *  parts: swap in the live key), ip_restricted (refused by your allowed server
 *  addresses), rate_limited (refused by the hourly or monthly limit), request_failed
 *  (the call failed, for example an invalid token). */
export type SetupStatusCode =
    | 'waiting' | 'complete' | 'missing_network' | 'network_unavailable' | 'missing_device'
    | 'device_unavailable' | 'test_mode' | 'test_complete' | 'ip_restricted' | 'rate_limited'
    | 'request_failed';

/** GET /v1/setup (since 0.5.0): whether your checks arrive complete, and what to fix. */
export interface SetupStatus {
    status: SetupStatusCode;
    /** At least one complete live-key check has arrived, ever. */
    complete: boolean;
    /** What the latest check showed, in words. */
    message: string;
    /** What to do next, or null when nothing is left to do. */
    next_step: string | null;
    /** ISO 8601 time of the latest check, or null. */
    last_check_at: string | null;
    complete_checks: number;
    /** ISO 8601 time of the latest complete check, or null. */
    last_complete_at: string | null;
    website: { confirmed: boolean; origin: string | null };
    /** Where and when the page script last reported in, or null. */
    script_seen: { origin: string; at: string } | null;
    site_id: string | null;
    /** Which key made this call. */
    key_type: 'live' | 'test';
    /** A link to the setup guide. */
    docs: string;
}

export class SentinelError extends Error {
    status?: number;
    body?: unknown;
}

export default class Sentinel {
    constructor(opts?: SentinelOptions);
    /** Throws SentinelError without a token (except for the four account events in
     *  AccountEventInput), for a value the API would ignore or misread, and when the
     *  API fails. */
    evaluate(input: EvaluateInput | AccountEventInput): Promise<EvaluateResult>;
    /** Look up an arbitrary public IP address (GET /v1/lookup/{ip}).
     *  Limited to public cloud-range/Tor evidence; unknown does not mean safe.
     *  Use evaluate() with a browser token for VPN/proxy evidence.
     *  Shares the hourly quota with evaluate() (one per account for the live
     *  keys; the test key has its own) and has its own monthly allowance. */
    lookup(ip: string): Promise<LookupResponse>;
    /** GET /v1/setup (since 0.5.0): after you submit your form once, whether that check
     *  arrived complete and what to fix. The answer is returned as the API sends it. */
    setupStatus(): Promise<SetupStatus>;
    /** Runs evaluate() and returns a boolean; throws SentinelError like evaluate()
     *  (no token, API failure). Default predicate (since 0.3.0):
     *  `r => r.decision === 'block'` — honors your dashboard rules and
     *  allow/block pins. Pass your own predicate for custom policy.
     *  A test, sandbox or sample answer returns true whatever the predicate
     *  (since 0.4.0), unless the client was made with allowTestResults. */
    shouldBlock(input: EvaluateInput | AccountEventInput, predicate?: (r: EvaluateResult) => boolean): Promise<boolean>;
    /** True for a test-token, sandbox or sample answer: never a verdict on a
     *  real visitor, so never a reason to let one through. */
    static isFixtureAnswer(result: EvaluateResult | null | undefined): boolean;
}

export { Sentinel };
