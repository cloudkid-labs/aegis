import { memoryScanStore } from "./test-support/memory-store";
import { describeScanStoreContract } from "./test-support/scan-store-contract";

describeScanStoreContract("memory", () => memoryScanStore());