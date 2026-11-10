'use strict';

function generateCombinedQuery(currentMediaQuery, nestedMediaQuery) {
  if (currentMediaQuery.length === 0) {
    return nestedMediaQuery;
  }
  return `${currentMediaQuery} and ${nestedMediaQuery}`;
}

exports.generateCombinedQuery = generateCombinedQuery;
//# sourceMappingURL=generateCombinedMediaQuery.cjs.js.map
