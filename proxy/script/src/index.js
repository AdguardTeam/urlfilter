// eslint-disable-next-line import/no-unresolved
import { nonce, cosmeticResult } from 'configuration';
import { applyCosmeticResult } from './cosmetic';

const contentScriptExecutionFlagToCheck = nonce || 'adgRunId';
if (!document[contentScriptExecutionFlagToCheck]) {
    // content script was already executed, doing nothing
    document[contentScriptExecutionFlagToCheck] = true;
    applyCosmeticResult(nonce, cosmeticResult);
}
