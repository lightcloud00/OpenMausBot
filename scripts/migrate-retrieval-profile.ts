import { resolve } from "node:path";

import { retrievalProfileSchema } from "../shared/retrieval-profile.ts";
import {
  applyRetrievalProfileMigration,
  previewRetrievalProfileMigration,
  rollbackRetrievalProfileMigration,
} from "../server/retrieval-profile-migration.ts";

function values(argv: string[], flag: string): string[] {
  const found: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === flag && argv[index + 1]) found.push(argv[index + 1]!);
  }
  return found;
}

function value(argv: string[], flag: string): string | undefined {
  return values(argv, flag).at(-1);
}

const argv = process.argv.slice(2);
const dataDir = value(argv, "--data-dir");
const botIds = values(argv, "--bot-id");
const profile = value(argv, "--profile");
const expectedDigest = value(argv, "--expected-digest");
const apply = argv.includes("--apply");
const rollback = value(argv, "--rollback");

if (rollback) {
  if (apply || dataDir || botIds.length || profile || expectedDigest) {
    throw new Error("--rollback <canonical receipt> is mutually exclusive with preview and apply arguments");
  }
  process.stdout.write(`${JSON.stringify(rollbackRetrievalProfileMigration({ receiptPath: resolve(rollback) }), null, 2)}\n`);
} else {
  const parsedProfile = retrievalProfileSchema.safeParse(profile);
  if (!dataDir || !botIds.length || !parsedProfile.success) {
    throw new Error(
      "usage: migrate-retrieval-profile.ts --data-dir <stopped data dir> --bot-id <exact id> [--bot-id <id>] --profile <off|task-scoped> [--apply --expected-digest <sha256>] | --rollback <canonical receipt>",
    );
  }

  const input = { dataDir: resolve(dataDir), botIds, profile: parsedProfile.data };
  if (!apply) {
    process.stdout.write(`${JSON.stringify(previewRetrievalProfileMigration(input), null, 2)}\n`);
  } else {
    if (!expectedDigest) throw new Error("--apply requires the exact --expected-digest from preview");
    process.stdout.write(`${JSON.stringify(applyRetrievalProfileMigration({ ...input, expectedDigest }), null, 2)}\n`);
  }
}
