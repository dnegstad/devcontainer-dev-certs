// @peculiar/x509 v2 transitively pulls in tsyringe, which requires the
// reflect-metadata polyfill before any module decorated with @injectable
// is imported. Same setup the extension test suites use.
import "reflect-metadata";
