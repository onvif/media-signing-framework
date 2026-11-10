/**
 * Checks if the animation is running at the moment.
 */ "use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
Object.defineProperty(exports, "isAnimationRunning", {
    enumerable: true,
    get: function() {
        return isAnimationRunning;
    }
});
function isAnimationRunning(animation) {
    if (animation.playState === 'running') {
        var _animation_effect;
        // Heads up!
        //
        // There is an edge case where the animation is running, but the overall progress is 0 or 1. In this case, we
        // consider the animation to be not running. If it will be reversed it will flip from 1 to 0, and we will observe a
        // glitch.
        // "overallProgress" is not supported in all browsers, so we need to check if it exists.
        // We will fall back to the currentTime and duration if "overallProgress" is not supported.
        if (animation.overallProgress !== undefined) {
            var _animation_overallProgress;
            const overallProgress = (_animation_overallProgress = animation.overallProgress) !== null && _animation_overallProgress !== void 0 ? _animation_overallProgress : 0;
            return overallProgress > 0 && overallProgress < 1;
        }
        var _animation_currentTime;
        const currentTime = Number((_animation_currentTime = animation.currentTime) !== null && _animation_currentTime !== void 0 ? _animation_currentTime : 0);
        var _animation_effect_getTiming_duration;
        const totalTime = Number((_animation_effect_getTiming_duration = (_animation_effect = animation.effect) === null || _animation_effect === void 0 ? void 0 : _animation_effect.getTiming().duration) !== null && _animation_effect_getTiming_duration !== void 0 ? _animation_effect_getTiming_duration : 0);
        return currentTime > 0 && currentTime < totalTime;
    }
    return false;
}
