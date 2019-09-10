function getCurrentScript() {
    let { currentScript } = document;
    if (!currentScript) {
        const scripts = document.getElementsByTagName('script');
        currentScript = scripts[scripts.length - 1];
    }
    return currentScript;
}

function logError(ex) {
    // eslint-disable-next-line no-console
    if (typeof console !== 'undefined' && console.error) {
        // eslint-disable-next-line no-console
        console.error('Error in AdGuard script');
        // eslint-disable-next-line no-console
        console.error(ex);
    }
}

export {
    getCurrentScript,
    logError,
};
