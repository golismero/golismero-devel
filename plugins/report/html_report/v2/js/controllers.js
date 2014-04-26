var app = angular.module('golismero-report', [
	'golismero-report-services',
	'ui.chart',
	'templates-app'
]);
app.config(['dataAccessProvider', function(dataAccessProvider){
    dataAccessProvider.setData(data);
}]);
app.filter('unique', function() {
    return function(input, key) {
        var unique = {};
        var uniqueList = [];
        for(var i = 0; i < input.length; i++){
            if(typeof unique[input[i][key]] == "undefined"){
                unique[input[i][key]] = "";
                uniqueList.push(input[i]);
            }
        }
        return uniqueList;
    };
});
app.value('charting', {
      pieChartOptions: {
        seriesDefaults: {
		  renderer: jQuery.jqplot.PieRenderer,
		  rendererOptions: {
		    showDataLabels: true,							
		    dataLabelPositionFactor: 1.15,
			diameter:150
		  }
		},
		legend: { show:true, location: 's'},
		grid: {drawBorder:false, shadow: false}
      }
    });
app.directive("tooltip", function(){
	return function(scope, element){
		element.tooltip();
	}
})
app.controller('reportController-chart', ['$scope', 'dataAccess','charting', function($scope, $dataAccess, charting){
	$scope.myChartOpts = charting.pieChartOptions;

	$scope.trimArray = function(array, numElements){
		var result = array.slice(0, numElements);

		if(array.length> numElements){
			var o = new Array();
			o[0] = 'Others';
			o[1] = 0;
			for(var i = numElements; i < array.length; i++){
				o[1]+=array[i][1];
			}
			result.push(o);
		}
		return result;
	}

	$scope.chartByType = [$scope.trimArray($dataAccess.getDataChartByType(), 10)];
	$scope.chartByTarget= [$scope.trimArray($dataAccess.getDataChartByTarget(), 10)];
	$scope.chartByCriticality =[$dataAccess.getDataChartByLevel()];
	
}])

app.controller('reportController', ['$scope', 'dataAccess', function($scope, $dataAccess){

	
	$scope.obtainLevel = function(level){
		switch(level){
			case 0: return "critical";
			case 1: return "high";
			case 2: return "middle";
			case 3: return "low";
			case 4: return "informational";
		}
	}

	$scope.vulnerabilities = $dataAccess.getVulnerabilitiesAngular();
	var arrayTargets =  $dataAccess.getAuditScope();
	//para que al seleccionarlo el filtro de todos
	arrayTargets.unshift("");
	$scope.targets =arrayTargets;

	var arrayVulnerabilities =  $dataAccess.getVulnerabilitiesAngular();
	arrayVulnerabilities.unshift({display_name:''});
    $scope.vulnerabilitiesSelect = arrayVulnerabilities;

    $scope.search = {resource:'', display_name:''};
    $scope.search.resource = '';

    $scope.dir = "+";
    $scope.field="level";
    $scope.order = $scope.dir+$scope.field;
    $scope.sortBy = function(field){
    	if(field == $scope.field){
			if($scope.dir == '+'){
    			$scope.dir = '-';
    		}else{
    			$scope.dir = '+';
    		}
    	}
    	$scope.field= field;
    	$scope.order = $scope.dir+$scope.field;
    }

    $scope.goTo = function(item){
    	$('body,html').stop(true,true).animate({
			scrollTop: $("[data-anchor='technical-"+item+"']").first().offset().top -80
		},1000);
    };

    $scope.dataTechnical = $dataAccess.getTargetTechnical();

    $scope.obtainTarget = function(id){
		return $dataAccess.getTargetById(id);	    		
	}

	$scope.summary = $dataAccess.getSummary();
	$scope.targetsResume= $dataAccess.getAuditScope();
	$scope.vulnsByLevel = $dataAccess.getDataVulnsByLevel();
}]);

