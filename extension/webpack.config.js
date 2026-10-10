const path = require('path')
const CopyPlugin = require('copy-webpack-plugin')

module.exports = {
  entry: {
    background: './src/background.ts',
    popup:      './src/popup.tsx',
    content:    './src/content.ts',
  },
  output: {
    path:     path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean:    true,
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js'],
  },
  module: {
    rules: [
      {
        test:    /\.tsx?$/,
        use:     'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'public', to: '.' },
        { from: 'src/popup.html', to: 'popup.html' },
      ],
    }),
  ],
}
