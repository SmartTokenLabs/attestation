const path = require('path');

module.exports = {
    entry: './src/bundle.ts',
    mode: "development",
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                exclude: /node_modules/,
                use: [
                    { loader: 'ts-loader', options: { transpileOnly: true } }
                ]
            }
            ]
    },
    devServer: {
        static: {
            directory: path.join(__dirname, '/'),
        },
        compress: true,
        port: 3015,
    },
    resolve: {
        extensions: [ '.tsx', '.ts', '.js' ],
        fallback:
            {
                "stream": require.resolve("stream-browserify") ,
                "assert": require.resolve("assert/")
            }

    },
    resolveLoader: {
        modules: ['node_modules'],
        extensions: ['.js', '.json'],
        mainFields: ['loader', 'main']
    },
    output: {
        filename: 'authenticator.bundle.js',
        path: path.resolve(__dirname, 'dist'),
    },
    // watch: true,
    watch: false,
    watchOptions: {
        aggregateTimeout: 200,
        poll: 1000,
        ignored: /node_modules/
    },
    optimization: {
        minimize: true
    }

};
