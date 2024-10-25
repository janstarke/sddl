import * as wasm from "sddl-wasm";


$('#convert').on('click', function (e) {
    var sddl=$('#sddl-string').val();
    var json = wasm.convert(sddl);
    $('#decoded').text(json);
})