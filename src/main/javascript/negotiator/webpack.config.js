const path = require('path');

module.exports = {
    entry: './src/index.js',
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                // use: 'ts-loader',
                exclude: /node_modules/,
            }
            ]
    },
    resolve: {
        extensions: [ '.tsx', '.ts', '.js' ],
    },
    resolveLoader: {
        modules: ['node_modules'],
        extensions: ['.js', '.json'],
        mainFields: ['loader', 'main']
    },
    output: {
        filename: 'negotiator.js',
        path: path.resolve(__dirname, 'dist'),
    },
    // watch: true,
    watch: false,
    watchOptions: {
        aggregateTimeout: 200,
        poll: 1000,
        ignored: /node_modules/
    }
};
