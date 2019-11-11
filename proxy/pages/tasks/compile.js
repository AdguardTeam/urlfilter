const fs = require('fs');
const console = require('console');
const { rollup } = require('rollup');
const postcss = require('postcss');
const assets = require('postcss-assets');
const inlinesvg = require('postcss-inline-svg');

const pkg = require('../package.json');
const config = require('./config');

if (!fs.existsSync(config.outputDir)) {
    fs.mkdirSync(config.outputDir);
}

async function buildJS(file) {
    console.info(`Start compiling ${file}`);

    const inputOptions = {
        input: `src/js/${file}`,
    };

    const outputOptions = {
        file: `${config.outputDir}/${file}`,
        format: 'iife',
        banner: `/* ${pkg.name} v${pkg.version} ${new Date().toDateString()} */`,
    };

    const bundle = await rollup(inputOptions);
    await bundle.write(outputOptions);

    const js = fs.readFileSync(outputOptions.file);
    fs.unlinkSync(outputOptions.file);

    console.info(`Finished compiling ${file}`);
    return js
}

async function buildCSS(file) {
    console.info(`Start compiling ${file}`);

    const css = fs.readFileSync(`src/css/${file}`);
    const result = await postcss([assets({
        loadPaths: ['src'],
    }), inlinesvg({
        paths: ['src'],
    })]).process(css, {
        from: `src/css/${file}`,
        to: `${config.outputDir}/${file}`,
    });

    console.info(`Finished compiling ${file}`);
    return result.css;
}

function buildHTML(file, js, css) {
    let html = fs.readFileSync(`src/${file}`).toString();

    const headIdx = html.indexOf('</head>');
    html = [
        html.slice(0, headIdx),
        '<style type="text/css">',
        css,
        '</style>',
        '<script type="text/javascript">',
        js,
        '</script>',
        html.slice(headIdx),
    ].join('\n');

    fs.writeFileSync(`${config.outputDir}/${file}`, html);
    console.info(`Result has been written to ${config.outputDir}/${file}`);
}

async function build() {
    const js = await buildJS('blocked.js');
    const css = await buildCSS('blocked.css');
    buildHTML('blocked.html', js, css);
}

build();