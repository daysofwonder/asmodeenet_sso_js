exports.command = function () {
    this.source(
        function (source) {
            console.log(source.value);
        }
    );

    return this;
};
