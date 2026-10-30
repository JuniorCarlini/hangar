// Values shared by the Playwright config, the server launcher and the tests.

// The throwaway owner created before the panel starts, without 2FA: an
// owner must have it, so the setup enrolls it in the browser (the panel
// opens nothing else first) and keeps its recovery codes for the logins and
// identity checks of the other tests.
export const OWNER_EMAIL = 'e2e@hangar.test';
export const OWNER_PASSWORD = 'pista-e2e-Runway-2026!';

// Every project the tests create starts with this prefix, so the teardown
// can remove their containers from the local Docker without touching
// anything else.
export const PROJECT_PREFIX = 'e2e-pw-';

// Where the logged-in session is kept between the setup and the tests.
export const AUTH_STATE = '.auth/owner.json';

// The owner's recovery codes, each good once (a TOTP code cannot be used
// twice within its 30 s, and the tests sign in more often than that).
export const RECOVERY_STATE = '.auth/recovery.json';
