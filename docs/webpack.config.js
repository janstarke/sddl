const CopyWebpackPlugin = require("copy-webpack-plugin");
const path = require('path');

module.exports = {

  performance: {
    maxAssetSize: 2048000,
    maxEntrypointSize: 2048000,
  },

  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bootstrap.js",
  },
  mode: "production",
  
  plugins: [
    new CopyWebpackPlugin({
      patterns: [{from: 'index.html'}]
    })
  ],
  
 experiments: {
  asyncWebAssembly: true
 }
};

//experiments.syncWebAssembly = true;