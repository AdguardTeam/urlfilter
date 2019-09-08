import * as utils from './utils';

/**
 * Cosmetic rules object.
 *
 * @typedef {Object} Cosmeticresult
 * @property {StylesResult} elementHiding - Element hiding rules
 * @property {StylesResult} css - CSS rules
 * @property {ScriptsResult} js - JS rules
 */

/**
 * Styles result object
 *
 * @typedef {Object} StylesResult
 * @property {Array<string>} generic - Generic styles
 * @property {Array<string>} specific - Styles specific to this website
 * @property {Array<string>} genericExtCss - Generic ExtCSS styles
 * @property {Array<string>} specificExtCss - ExtCSS styles specific to this website
 */

/**
 * Scripts result object
 *
 * @typedef {Object} StylesResult
 * @property {Array<function>} generic - Generic functions
 * @property {Array<function>} specific - Functions specific to this website
 */

/**
 * Creates CSS rules from the cosmetic result
 * @param {*} rules rules
 * @param {*} style (optional) CSS style. For instance, `display: none`.
 */
function getCssRules(rules, style) {
    const cssRules = [];

    rules.forEach((rule) => {
        if (style) {
            cssRules.push(`${rule} { ${style} }`);
        } else {
            cssRules.push(rule);
        }
    });

    return cssRules;
}

/**
 * Creates a <style> tag that will be added to this page
 * @param {string} nonce - nonce string (that is added to the CSP of this page)
 * @param {CosmeticResult} cosmeticResult - cosmetic rules
 */
function createStyle(nonce, cosmeticResult) {
    const style = document.createElement('style');
    style.setAttribute('nonce', nonce);
    style.setAttribute('type', 'text/css');

    const cssRules = [
        ...getCssRules(cosmeticResult.elementHiding.generic, 'display: none!important'),
        ...getCssRules(cosmeticResult.elementHiding.specific, 'display: none!important'),
        ...getCssRules(cosmeticResult.css.generic),
        ...getCssRules(cosmeticResult.css.specific),
    ];

    const cssTextNode = document.createTextNode(cssRules.join('\n'));
    style.appendChild(cssTextNode);
    return style;
}

/**
 * Applies cosmetic rules to the page
 *
 * @param {string} nonce - nonce string (that is added to the CSP of this page)
 * @param {CosmeticResult} cosmeticResult - cosmetic rules
 */
function applyCosmeticResult(nonce, cosmeticResult) {
    const style = createStyle(nonce, cosmeticResult);

    const currentScript = utils.getCurrentScript();
    const rootElement = currentScript.parentNode;
    let insertBeforeElement = currentScript;
    if (currentScript.parentNode !== rootElement) {
        insertBeforeElement = null;
    }
    rootElement.insertBefore(style, insertBeforeElement);

    /* Override styleEl's disabled" property for forever enabled */
    const disabledDescriptor = {
        get: () => false,
        set: () => false,
    };
    Object.defineProperty(style, 'disabled', disabledDescriptor);
    Object.defineProperty(style.sheet, 'disabled', disabledDescriptor);
}

export {
    // eslint-disable-next-line import/prefer-default-export
    applyCosmeticResult,
};
