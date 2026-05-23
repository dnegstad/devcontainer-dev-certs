// Loaded before every test file. The shared cert stack pulls in
// @peculiar/x509, which transitively requires `reflect-metadata` to be
// loaded before any module decorated with @injectable is imported (tsyringe
// reads the polyfill at module init time).
import "reflect-metadata";
