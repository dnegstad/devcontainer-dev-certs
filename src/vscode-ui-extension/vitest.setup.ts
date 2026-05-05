// Loaded before every test file. @peculiar/x509 v2 transitively pulls in
// tsyringe, which requires the reflect-metadata polyfill to be present
// before any module decorated with @injectable is imported.
import "reflect-metadata";
