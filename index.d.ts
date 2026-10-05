export interface EvaluateDetails {
    ip: string;
    cc: string;
    vpn: boolean;
    proxied: boolean;
    dch: boolean;
    anon: boolean;
    crawler?: boolean;
    service?: string;
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
}

export interface NetworkSignals {
    vpn: boolean;
    proxy: boolean;
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

export interface DeviceSignals {
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
}

export type ReasonCode =
    | 'vpn_detected' | 'proxy_detected' | 'datacenter_asn' | 'tor_exit_node'
    | 'anonymous_network' | 'antidetect_browser' | 'automation_detected'
    | 'emulator_detected' | 'virtual_machine' | 'ip_blocklisted' | 'private_browsing'
    | 'high_activity_device' | 'multi_account_device' | 'disposable_email';

export interface EmailSignals {
    /** True when the address uses a disposable/burner domain */
    disposable: boolean;
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
    /** Machine-readable reason codes for the verdict */
    reasons: ReasonCode[];
    evaluated_in_ms: number;
    /** Present when the optional `email` input was supplied */
    email?: EmailSignals;
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
    /** Present and true when the network layer was unavailable */
    degraded?: boolean;
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
}

export interface EvaluateInput {
    /** Client-side Sentinel token from the frontend SDK */
    token: string;
    /** Optional device event id for device-layer signals */
    fingerprintEventId?: string;
    /** Optional account/user id — enables multi-accounting detection
     *  (device.linked_accounts / device.multi_account) */
    accountId?: string;
    /** Optional signup email — adds `email.disposable` to the response
     *  (burner domains escalate allow → review). Checked transiently,
     *  never stored or logged. */
    email?: string;
}

export class SentinelError extends Error {
    status?: number;
    body?: unknown;
}

export default class Sentinel {
    constructor(opts?: SentinelOptions);
    evaluate(input: EvaluateInput): Promise<EvaluateResult>;
    /** Look up an arbitrary public IP address (GET /v1/lookup/{ip}).
     *  Limited to public cloud-range/Tor evidence; unknown does not mean safe.
     *  Use evaluate() with a browser token for VPN/proxy evidence.
     *  Shares the hourly quota with evaluate() (one per account for the live
     *  keys; the test key has its own) and has its own monthly allowance. */
    lookup(ip: string): Promise<LookupResponse>;
    /** Runs evaluate() and returns a boolean; throws SentinelError like evaluate()
     *  (no token, API failure). Default predicate (since 0.3.0):
     *  `r => r.decision === 'block'` — honors your dashboard rules and
     *  allow/block pins. Pass your own predicate for custom policy. */
    shouldBlock(input: EvaluateInput, predicate?: (r: EvaluateResult) => boolean): Promise<boolean>;
}

export { Sentinel };
