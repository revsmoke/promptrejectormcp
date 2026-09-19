// Loaded before each test. This prevents accidental networking in trusted tests;
// it is not a security sandbox for hostile JavaScript.
import fs = require("node:fs");
import net = require("node:net");
import tls = require("node:tls");
import dgram = require("node:dgram");
import { syncBuiltinESMExports } from "node:module";

const logPath = process.env.OFFLINE_NETWORK_LOG;
if (!logPath) throw new Error("Offline guard requires a violation log");
const allowLoopback = process.env.OFFLINE_ALLOW_LOOPBACK === "1";

function deny(transport: string): never {
    // Synchronous persistence survives caught errors and process.exit(0).
    // Never log URLs, request bodies, headers, or credentials.
    fs.appendFileSync(logPath!, JSON.stringify({ transport, reason: "network disabled by offline test runner" }) + "\n");
    throw new Error(`Offline test blocked ${transport}`);
}

function isLoopback(host: unknown): boolean {
    return host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

function hostFromArgs(args: unknown[]): unknown {
    // Node internally normalizes Socket.connect arguments into an array.
    if (Array.isArray(args[0])) return hostFromArgs(args[0]);
    if (typeof args[0] === "object" && args[0] !== null) {
        const options = args[0] as { host?: unknown; path?: unknown };
        return options.path ? undefined : options.host;
    }
    return typeof args[0] === "number" ? args[1] : undefined;
}

const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (this: net.Socket, ...args: unknown[]) {
    if (!allowLoopback || !isLoopback(hostFromArgs(args))) deny("socket");
    return Reflect.apply(originalConnect, this, args);
} as typeof originalConnect;

const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function (this: net.Server, ...args: unknown[]) {
    if (!allowLoopback || !isLoopback(hostFromArgs(args))) deny("listen");
    return Reflect.apply(originalListen, this, args);
} as typeof originalListen;

const originalTlsConnect = tls.connect;
tls.connect = function (...args: unknown[]) {
    if (!allowLoopback || !isLoopback(hostFromArgs(args))) deny("tls");
    return Reflect.apply(originalTlsConnect, tls, args);
} as typeof originalTlsConnect;

// No baseline suite requires datagrams, including marked HTTP integration tests.
dgram.Socket.prototype.send = function () { deny("datagram"); } as typeof dgram.Socket.prototype.send;
dgram.Socket.prototype.bind = function () { deny("datagram-bind"); } as typeof dgram.Socket.prototype.bind;

const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (!allowLoopback || !isLoopback(url.hostname)) deny("fetch");
    return originalFetch(input, init);
};
syncBuiltinESMExports();
