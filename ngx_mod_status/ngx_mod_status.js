
window.onload = () => {
	//
	var script_name = "basic_status";
	var refresh = 500;

	//
	var has_recording = window.sessionStorage.getItem("__mds_has_recording__");
	has_recording = has_recording ? parseInt(has_recording) : 0;

	if(!record_msec_left && !has_recording) {
		document.getElementById('dot').className = "dot_red";

		window.sessionStorage.setItem("__mds_has_recording__", "1");

		var host = window.location.host;

		const url = window.location.origin+"/"+script_name+"?cmd=start_rec";

		fetch(url, {method: "GET"})
		.then(data => {
			setTimeout(() => {
				location.reload();
			}, refresh);
		});

	} else if(!record_msec_left) {
		window.sessionStorage.setItem("__mds_has_recording__", "0");
		document.getElementById('dot').className = "dot_green";
	} else {
		document.getElementById('dot').className = "dot_red";
		setTimeout(() => {
			location.reload();
			//}, record_msec_left+100);
		}, refresh);
	}

	//
	document.getElementById('stats').innerHTML = "\nPIDs: "+stats_arr.map((el, idx) => el.pid + (idx==stats_arr.length-1 ? "" : ", ")).join('')+"\n";

	var cell_style = "\"white-space: nowrap; padding: 0 10px 0 10px;\"";
	var first_cell_style = "\"white-space: nowrap; padding: 0 10px 0 0px;\"";

	var table_header = "<tr>\
		<td style="+first_cell_style+"><b>PID</b></td>\
		<td style="+cell_style+"><b>Con Id</b></td>\
		<td style="+cell_style+"><b>R</b></td>\
		<td style="+cell_style+"><b>W</b></td>\
		<td style="+cell_style+"><b>P</b></td>\
		<td style="+cell_style+"><b>Port</b></td>\
		<td style="+cell_style+"><b>Client</b></td>\
		<td style="+cell_style+"><b>Vhost</b></td>\
		<td style="+cell_style+"><b>Request</b></td>\
	</tr>";

	document.getElementById('stats').innerHTML += "\nActive connections:\n\n"+"<table>"+table_header+
	stats_arr.map((el, idx) => {
		return el.acc.map(el_acc => {
			return ("<tr><td style="+first_cell_style+">"+el.pid+"</td>")+el_acc.map((el_stat, el_stat_idx) =>
					"<td><div style="+cell_style+">" + el_stat+"</div></td>").join('')+"</tr>";
		}).join('');
	}).join('')+"</table>";

	document.getElementById('stats').innerHTML += "\nLingering connections:\n\n"+"<table>"+table_header+
	stats_arr.map((el, idx) => {
		return el.log.map(el_acc => {
			return ("<tr><td style="+first_cell_style+">"+el.pid+"</td>")+el_acc.map((el_stat, el_stat_idx) =>
					"<td><div style="+cell_style+">" + el_stat+"</div></td>").join('')+"</tr>";
		}).join('');
	}).join('')+"</table>";/**/

	document.getElementById('stats').innerHTML += "\n\n/"+script_name+"?refresh=1000 - change recording time in ms\n";

	document.getElementById('stats').innerHTML += "/"+script_name+"?expl=[0|1] - activate experimental lingering\n";

	document.getElementById('is_recording').innerHTML = record_msec_left+"/"+record_msec;

	document.getElementById('is_recording').innerHTML += expl ? "\n\nExperimental lingering active" : "";


}
