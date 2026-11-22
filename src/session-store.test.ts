import { memorySessionStore } from "./session-store";
import { describeSessionStoreContract } from "./test-support/session-store-contract";

describeSessionStoreContract("memory", memorySessionStore);