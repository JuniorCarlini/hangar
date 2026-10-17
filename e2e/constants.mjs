// Values shared by the Playwright config, the server launcher and the tests.

// The throwaway owner created before the panel starts (no 2FA: the tests
// log in with the password only).
export const OWNER_EMAIL = 'e2e@hangar.test';
export const OWNER_PASSWORD = 'pista-e2e-Runway-2026!';

// Every project the tests create starts with this prefix, so the teardown
// can remove their containers from the local Docker without touching
// anything else.
export const PROJECT_PREFIX = 'e2e-pw-';

// Where the logged-in session is kept between the setup and the tests.
export const AUTH_STATE = '.auth/owner.json';
