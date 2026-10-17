import { execFileSync } from 'node:child_process';

import { PROJECT_PREFIX } from '../constants.mjs';

function docker(...args: string[]): string {
  return execFileSync('docker', args, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
}

// dockerCLI reports whether the docker command reaches an engine. The
// panel itself is the final word (see hasDocker in helpers.ts); this is
// only used to clean up.
function dockerCLI(): boolean {
  try {
    docker('info', '--format', '{{.ServerVersion}}');
    return true;
  } catch {
    return false;
  }
}

// removeTestContainers deletes the containers, volumes and networks of the
// projects the tests created (label hangar.project starting with the prefix).
export function removeTestContainers() {
  if (!dockerCLI()) return;
  const ours = (kind: string, format: string) =>
    docker(kind, 'ls', ...(kind === 'container' ? ['-a'] : []), '--filter', 'label=hangar.managed=true', '--format', format)
      .split('\n')
      .filter(Boolean)
      .map((line) => line.split(' '))
      .filter(([, project]) => project?.startsWith(PROJECT_PREFIX))
      .map(([id]) => id);

  const containers = ours('container', '{{.ID}} {{.Label "hangar.project"}}');
  if (containers.length) docker('rm', '-f', '-v', ...containers);
  const volumes = ours('volume', '{{.Name}} {{.Label "hangar.project"}}');
  if (volumes.length) docker('volume', 'rm', '-f', ...volumes);
  const networks = ours('network', '{{.ID}} {{.Label "hangar.project"}}');
  if (networks.length) docker('network', 'rm', ...networks);
  // Images built from Git carry the project label too.
  const images = ours('image', '{{.ID}} {{.Label "hangar.project"}}');
  if (images.length) docker('image', 'rm', '-f', ...new Set(images));
}
