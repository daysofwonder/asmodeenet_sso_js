// http://eslint.org/docs/user-guide/configuring

module.exports = {
    root: true,
    // parser: 'babel-eslint',
    parserOptions: {
        sourceType: 'module'
    },
    env: {
        browser: true,
        jasmine: true
    },
    // https://github.com/standard/standard/blob/master/docs/RULES-en.md
    extends: 'standard',
    // add your custom rules here
    'rules': {
        'semi': ['error', 'always'],
        'indent': ['error', 4],
        // allow paren-less arrow functions
        'arrow-parens': 0,
        // allow async-await
        'generator-star-spacing': 0,
        'array-bracket-newline': 0
    }
};
