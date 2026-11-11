// Lets jest load the project's ESM source (server + client) through babel-jest.
module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' } }]
  ]
};
