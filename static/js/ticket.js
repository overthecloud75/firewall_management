function handleClick(data, index){
    $('#modalForm').modal('show'); ;
    $('#id').val(data._id);
    $('#timestamp').val(data.timestamp);
    $("#timestamp").attr("disabled",true);
    $('#ticket').val(data.ticket);
    $("#ticket").attr("disabled",true);
    $('#ip').val(data.ip); 
	$("#ip").attr("disabled",true);
    $('#geo_ip').val(data.geo_ip); 
	$("#geo_ip").attr("disabled",true); 
    $('#attack_no').val(data.attack_no); 
	$("#attack_no").attr("disabled",true); 
    $('#fix').val(data.fix); 
    document.getElementById("btn-save").style.display = "block";
    document.getElementById("btn-delete").style.display = "none";
};
$("#btn-save").click(function(e) {
	e.preventDefault();
	if(!confirm('정말로 저장하시겠습니다.?')) return;
	$('#fw-form')[0].submit();
});