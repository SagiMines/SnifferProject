<?php
	/* Database connection settings */
	$serverName = "."; //serverName\instanceName
	$connectionInfo = array( "Database"=>"Boss sniffer");
	$conn = sqlsrv_connect( $serverName, $connectionInfo);
	
	if($conn) {
	echo "Connection established.<br />";
	}else{
		echo "Connection could not be established.<br />";
		die(print_r( sqlsrv_errors(), true));
	}
	
	$data1 = '';
	$data2 = '';
	$data3 = '';
	$data4 = '';

	//query to get data from the table
	$sql = "SELECT * FROM Web_info";
    $result = sqlsrv_query($conn, $sql);
	
	//
	$distinct = "SELECT src_ip, COUNT(*) AS 'count' FROM Web_info GROUP BY src_ip ORDER BY count";
	$result2 = sqlsrv_query($conn, $distinct);
	
	$sql3 = "SELECT dst_ip , COUNT(*) AS 'count' FROM temp1 WHERE dst_ip not LIKE '%10.100%' GROUP BY dst_ip ORDER BY count DESC;";
	$result3 = sqlsrv_query($conn, $sql3);

	//loop through the returned data
	while ($row = sqlsrv_fetch_array($result,SQLSRV_FETCH_ASSOC)) {

		$data1 = $data1 . '"'. $row['src_port'] .'",';
		$data2 = $data2 . '"'. $row['dst_port'] .'",';
		
	}
	
	$data1 = trim($data1,",");
	$data2 = trim($data2,",");	
?>

<!DOCTYPE html>
<html>
	<head>
    	<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.7.2/Chart.bundle.min.js"></script>
		<title>Sniffer</title>

		<style type="text/css">			
			body{
				font-family: Arial;
			    margin: 80px 100px 10px 100px;
			    padding: 0;
			    color: white;
			    text-align: center;
			    background: #555652;
			}
			
			h2 {
			font-family: Impact, Charcoal, sans-serif;
			font-size: 80px;
			margin-bottom: 30px;
			}
			
			head{
				font-family: Arial;
			    margin: 80px 100px 10px 100px;
			    padding: 0;
			    color: white;
			    text-align: center;
			    background: #555652;
			}

			.container {
				color: #E8E9EB;
				background: #222;
				border: #555652 1px solid;
				padding: 10px;
			}
		</style>
	</head>
	<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript">
      google.charts.load('current', {'packages':['corechart']});
      google.charts.setOnLoadCallback(drawChart);

      function drawChart() {

        var data = google.visualization.arrayToDataTable([
          ['Site', 'Visits'],
		  <?php
				  while($row = sqlsrv_fetch_array($result3)) {
					 // $row['dst_ip'] = gethostbyaddr($row['dst_ip']);
				  echo "['".$row['dst_ip']."', ".$row['count']."],";
				  }
		  ?>   
        ]);

        var options = {
          is3D: true,
          backgroundColor: { fill: "#222" },
		  chartArea: {'backgroundColor':'#222'},
		  legend:{display: true, position: 'top', textStyle: {color: 'white'}}
        };

        var chart = new google.visualization.PieChart(document.getElementById('piechart'));

        chart.draw(data, options);
      }
	</script>
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript">
      google.charts.load('current', {'packages':['bar']});
      google.charts.setOnLoadCallback(drawChart);

      function drawChart() {
        var data = google.visualization.arrayToDataTable([
			['IP','Amount'],
          <?php
				  while($row = sqlsrv_fetch_array($result2)) {
					  echo "['".$row['src_ip']."', '".$row['count']."'],";
				  }
		  ?>
        ]);

        var options = {
		  backgroundColor: { fill: "#222" },
		  chartArea: {'backgroundColor':'#222'},
		  colors:['#07f7e7'],
		  legend:{display: true, position: 'top', textStyle: {color: 'white'}}
        };

        var chart = new google.charts.Bar(document.getElementById('columnchart_material'));

        chart.draw(data, google.charts.Bar.convertOptions(options));
      }
    </script>
	
	<body>
	<h2>Sniffer's Statistics</h2>
	<div class="container">	
	<h1>Traffic per site</h1>   
	<div id="piechart" style="width: 100%; height: 65vh; border: 1px solid #555652; margin-top: 10px;"></div>
	<h1>Traffic by IP</h1>    	
	<div id="columnchart_material" style="width: 100%; height: 65vh; border: 1px solid #555652; margin-top: 10px;"></div>	
	
	    <div class="container">	
	    <h1>Traffic by port</h1>       
			<canvas id="chart" style="width: 100%; height: 65vh; background: #222; border: 1px solid #555652; margin-top: 10px;"></canvas>

					   <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
			
			<script>
			//Traffic by port
				var ctx = document.getElementById("chart").getContext('2d');
    			var myChart = new Chart(ctx, {
        		type: 'line',
		        data: {
		            labels: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20],
		            datasets: 
		            [{
		            	label: 'Source port',
		                data: [<?php echo $data1; ?>],
		                backgroundColor: 'transparent',
		                borderColor:'rgba(0,255,255)',
		                borderWidth: 3	
		            },
					{
		            	label: 'Destination port',
		                data: [<?php echo $data2; ?>],
		                backgroundColor: 'transparent',
		                borderColor:'rgba(255, 165, 0)',
		                borderWidth: 3	
		            }]
		        },
		     
		        options: {
		            scales: {scales:{yAxes: [{beginAtZero: false}], xAxes: [{autoskip: true, maxTicketsLimit: 20}]}},
		            tooltips:{mode: 'index'},
		            legend:{display: true, position: 'top', labels: {fontColor: 'rgb(255,255,255)', fontSize: 16}}
		        }
		    });
			</script>
	    </div>
	    
	</body>
</html>