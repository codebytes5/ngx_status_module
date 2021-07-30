
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


	document.getElementById('stats').innerHTML = "\nActive connections:\n\n"+stats_arr.map((el, idx) => {
		return ("proc "+idx+":\n\n")+el.acc.map(el_acc => {
			return el_acc.map((el_stat, el_stat_idx) => el_stat_idx ? el_stat : el_stat).join(' ');
		}).join('\n');
	}).join('\n\n');

	document.getElementById('stats').innerHTML += "\n\nLingering connections:\n\n"+stats_arr.map((el, idx) => {
		return ("proc "+idx+":\n\n")+el.log.map(el_acc => {
			return el_acc.map((el_stat, el_stat_idx) => el_stat_idx ? el_stat : el_stat).join(' ');
		}).join('\n');
	}).join('\n\n');/**/

	document.getElementById('stats').innerHTML += "\n\n/"+script_name+"?refresh=1000 - change recording time in ms\n";

	document.getElementById('stats').innerHTML += "/"+script_name+"?expl=[0|1] - activate experimental lingering\n";

	document.getElementById('is_recording').innerHTML = record_msec_left+"/"+record_msec;

	document.getElementById('is_recording').innerHTML += expl ? "\n\nExperimental lingering active" : "";


}
