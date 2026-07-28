import * as fs from "fs";
import * as path from "path";
import { generateCertificate, exportRootPfx } from "@devcontainer-dev-certs/shared";

const home = process.argv[2];
const rootDir = path.join(home, ".dotnet/corefx/cryptography/x509stores/root");
fs.mkdirSync(rootDir, { recursive: true });
fs.mkdirSync(path.join(home, ".dotnet/corefx/cryptography/x509stores/my"), { recursive: true });
fs.mkdirSync(path.join(home, ".aspnet/dev-certs/trust"), { recursive: true });

const now = new Date();
const { cert, thumbprint } = await generateCertificate(
  new Date(now.getTime() - 2 * 86400_000),
  new Date(now.getTime() - 1 * 86400_000)
);
const tmpOut = fs.mkdtempSync("/tmp/expired-ca-");
await exportRootPfx(cert, tmpOut);
fs.renameSync(path.join(tmpOut, "aspnetcore-dev-root.pfx"), path.join(rootDir, `${thumbprint}.pfx`));
console.log("planted expired CA-only root PFX:", thumbprint);
