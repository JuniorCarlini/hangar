import { removeTestContainers } from './tests/docker';

// The panel's data directory goes away with the server, but containers,
// volumes and networks live in the local Docker: remove the ones the tests
// created (projects named with PROJECT_PREFIX), and nothing else.
export default function teardown() {
  removeTestContainers();
}
