"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    isTruncatableBreadcrumbContent: function() {
        return _truncateBreadcrumb.isTruncatableBreadcrumbContent;
    },
    partitionBreadcrumbItems: function() {
        return _partitionBreadcrumbItems.partitionBreadcrumbItems;
    },
    truncateBreadcrumLongTooltip: function() {
        return _truncateBreadcrumb.truncateBreadcrumLongTooltip;
    },
    truncateBreadcrumbLongName: function() {
        return _truncateBreadcrumb.truncateBreadcrumbLongName;
    }
});
const _partitionBreadcrumbItems = require("./partitionBreadcrumbItems");
const _truncateBreadcrumb = require("./truncateBreadcrumb");
