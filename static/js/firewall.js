$("#update").click(function(e) {
    e.preventDefault();
    $('#modalForm').modal('show');
    $('#ip').val(''); 
    document.getElementById("btn-save").style.display = "block";
    document.getElementById("btn-delete").style.display = "none";
});
function handleClick(event, data, index){
    $('#modalForm').modal('show'); 
    $('#no').val(index);
    $('#ip').val(data.ip); 
    $('#ip_class').val(data.ip_class);
    $('#port').val(data.port);
    $('#block').val(data.block);
    document.getElementById("btn-save").style.display = "none";
    document.getElementById("btn-delete").style.display = "block";
};
$("#btn-save").click(function(e) {
	e.preventDefault();
	if(!confirm('정말로 저장하시겠습니다.?')) return;
	$('#fw-form')[0].submit();
});
$("#btn-delete").click(function(e) {
	e.preventDefault();
	if(!confirm('정말로 삭제하시겠습니다.?')) return;

    let formData = new FormData();
    formData.append('csrf_token', $('#csrf_token').val());
    formData.append('ip', $('#ip').val());
    formData.append('ip_class', $('#ip_class').val());
    formData.append('protocol', $('#protocol').val());
    formData.append('port', $('#port').val());
    formData.append('block', $('#block').val());
    $.ajax({
        url: "/manage/api/delete",
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (result) {
            $('tbody tr').eq($('#no').val()).remove();
        }
    });
    $('#modalForm').modal('hide'); 
});