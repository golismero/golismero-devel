angular.module('golismero-report-services', [])

.provider('dataAccess', [ function(){	
	this.data = {};

	this.$get = function(){
		var data = this.data;
		var targetsMap = {};
		var service = {};
		var auditScope = data.audit_scope;
		$.each(this.data.resources, function(key, val){		
			targetsMap[key] = val;
		});
		
		service.getTargetById = function(id){
			if(id){
				var d = targetsMap[id];
				if(d){
				    return d.display_content;
				}
			}
			return "";
		};

		var vulnerabilitiesByTarget = [];
		$.each(this.data.vulnerabilities, function(key, val){		
			//agrego un campo que es el name que le das al id. Sirve para cuando se quiere modificar el id,
			//realmente no se modifica el id si no un nombre que l epones al id
			val.nameIdentity = val.identity;
			val.resource = service.getTargetById(val.target_id);
			if(!vulnerabilitiesByTarget[val['resource']]){
				vulnerabilitiesByTarget[val['resource']] = 0;
			}
			vulnerabilitiesByTarget[val['resource']]+=1;
		});

		service.getSummary = function(){
			return data.summary;
		}

		service.getDataVulnsByLevel= function(){
			return data.stats.vulns_by_level;
		}
		service.updateDataVulnsByLevel = function(){
			data.stats.vulns_by_level.High=0;
			data.stats.vulns_by_level.Middle=0;
			data.stats.vulns_by_level.Critical=0;
			data.stats.vulns_by_level.Informational=0;
			data.stats.vulns_by_level.Low=0;
			$.each(data.vulnerabilities, function(key, val){		
				switch(val.level){
					case 0: data.stats.vulns_by_level.Critical++;break;
					case 1: data.stats.vulns_by_level.High++;break;
					case 2: data.stats.vulns_by_level.Middle++;break;
					case 3: data.stats.vulns_by_level.Low++;break;
					case 4: data.stats.vulns_by_level.Informational++;break;
				};
			});
		}

		service.updateDataVulnsByType = function(){
			data.stats.vulns_by_type = {};
			
			$.each(data.vulnerabilities, function(key, val){
				if(!data.stats.vulns_by_type[val.display_name])	{
					data.stats.vulns_by_type[val.display_name] = 0;
				}	
				data.stats.vulns_by_type[val.display_name]++;
			});
		}

		service.getDataChartByType = function(){
			var dataChar = new Array();
			$.each(data.stats.vulns_by_type, function(key, val){		
				var o = new Array();
				o[0] = key;
				o[1] = val;
				dataChar.push(o);
			});
			return dataChar;
		}

		
		service.getDataChartByTarget = function(){
			var dataChar = new Array();
			$(service.getAuditScope()).each(function(index,v){
				var o = new Array();
				o[0] = v;
				o[1] = vulnerabilitiesByTarget[v];
				if(o[1] >0){
					dataChar.push(o);
					}
			});
			return dataChar;
		};
		service.getAuditScope = function(){
			var targetsScope = new Array();
			if(auditScope.domains){
				$.each(auditScope.domains, function(key, value){
					targetsScope.push(value);
				});
			}
			if(auditScope.web_pages){
				$.each(auditScope.web_pages, function(key, value){
					targetsScope.push(value);
				});
			}
			if(auditScope.addresses){
				$.each(auditScope.addresses, function(key, value){
					targetsScope.push(value);
				});
			}
			if(auditScope.roots){
				$.each(auditScope.roots, function(key, value){
					targetsScope.push(value);
				});
			}
			return targetsScope;
		};
		
		service.getDataChartByLevel = function(){
			var dataChar = new Array();

			$.each(data.stats.vulns_by_level, function(key, val){		
				var o = new Array();
				o[0] = key;
				o[1] = val;
				dataChar.push(o);
			});

			return dataChar;
		};
		service.getTargetTechnical = function(){
			return data.vulnerabilities;
		};
		service.getStats = function(){
			return data.stats;
		};
		
		service.initDataTarget = function(vulns){
			
			var targetsMapTemp = {};
			vulnerabilitiesByTarget = [];
			for(val in vulns){
				if(!targetsMapTemp[vulns[val].target_id]){
					targetsMapTemp[vulns[val].target_id] = targetsMap[vulns[val].target_id];
				}
				if(!vulnerabilitiesByTarget[vulns[val]['resource']]){
					vulnerabilitiesByTarget[vulns[val]['resource']] = 0;
				}
				vulnerabilitiesByTarget[vulns[val]['resource']]+=1;
			}
			targetsMap = targetsMapTemp;
		}
		service.getTargets = function(){
			return targetsMap;
		}

		return service;
	}
	this.setData = function(data) {
        this.data = data;
    };
}])

.factory('pdfService', ['dataAccess', function($dataAccess){
	var service = {};

	service.downloadPdf = function(generalInfo, docDefinition){
		//abrir porque funciona en chrome y firefox
		if(generalInfo.action==="open"){
			pdfMake.createPdf(docDefinition).open();
		}else{
			pdfMake.createPdf(docDefinition).download();
		}
		//
	};
	function createHeader(generalInfo){
		var header = {
				    columns:[
				        {
			                width: 80,
	                        image: generalInfo.image
				        },
				        {
				            width: '*',
				            style:"header",
		                    text: [generalInfo.auditName]
				        }
				    ],
				    columnGap: 50
				};
		return header;
	}

	function createSummary(generalInfo){
		var summary = generalInfo.summary.summary;
		var targets = "";
		var auditScope = generalInfo.summary.auditScope;
		if(generalInfo.summary.showTargets){
			for(var i in auditScope){
				targets+=auditScope[i].display_content+"; ";
			}
		}
		var stats = generalInfo.summary.stats;
		
		var summaryjson= {
			        table: {
		                headerRows:1,
		                widths: [ ],		        
		                body: [
		                	[],//header
		                	[]//content
		                ]
		          }
			    };
		if(generalInfo.summary.showTargets){
			summaryjson.table.widths.push('*');
			summaryjson.table.body[0].push({ text: 'Targets', style:'th' });
			summaryjson.table.body[1].push({text:targets, style:'text'});
		}
		if(generalInfo.summary.showTimes){
			summaryjson.table.widths.push('*');
			summaryjson.table.body[0].push({ text: 'Time', style:'th' });
			summaryjson.table.body[1].push([
		                      	{ text: 'Start:', style:'h3' },{text:summary.start_time, style:'text'},
		                      	{ text: 'End:', style:'h3' },{text:summary.stop_time, style:'text'},
		                      	{ text: 'Total:', style:'h3' },{text:summary.run_time, style:'text'}
	                      	]);
		}
		if(generalInfo.summary.showTotals){
			summaryjson.table.widths.push('*');
			summaryjson.table.body[0].push( { text: 'Vulnerabilities', style:'th' });
			summaryjson.table.body[1].push([
		                      	{ text: 'Total:', style:'h3' },{text:(stats.High + stats.Low + stats.Middle + stats.Critical + stats.Informational)+'', style:'text'},
		                      	{
		                      		columns:[
		                      			[{ text: 'Critical:', style:['h3', 'critical'] },{text:stats.Critical.toString(), style:'text'}], 
			                    		[{ text: 'High:', style:['h3', 'high'] },{text:stats.High.toString(), style:'text'}]
		                      		]
		                      	},
		                      	{
		                      		columns:[
		                      			[{ text: 'Middle:', style:['h3', 'middle'] },{text:stats.Middle.toString(), style:'text'}], 
			                    		[{ text: 'Low:', style:['h3', 'low'] },{text:stats.Low.toString(), style:'text'}]
		                      		]
		                      	},			                    
			                    { text: 'Informational:', style:['h3', 'informational']},{text:stats.Informational.toString(), style:'text'}
		                    ]);
		}

		return summaryjson;
	}
	function createCharts(generalInfo, chartLevel, chartType, chartTarget){
		
		var chartsjson= {
			        table: {
		                headerRows:1,
		                widths: [ ],		        
		                body: [
	                  	[],
	                  	[]
		            ]
		          }
			    };
		if(generalInfo.charts.showVulnCriticality){
			chartsjson.table.widths.push("*");
			chartsjson.table.body[0].push({ text: 'Vulnerabilities by criticality', style:'th' });
			chartsjson.table.body[1].push({image:chartLevel, width: 150, aligment:'middle'});
		}
		if(generalInfo.charts.showVulnsType){
			chartsjson.table.widths.push("*");
			chartsjson.table.body[0].push({ text: 'Vulnerabilities by type', style:'th' });
			chartsjson.table.body[1].push({image:chartType, width: 150, aligment:'middle'});
		}
		if(generalInfo.charts.showVulnsTarget){
			chartsjson.table.widths.push("*");
			chartsjson.table.body[0].push({ text: 'Vulnerabilities by target', style:'th' });
			chartsjson.table.body[1].push({image:chartTarget, width: 150, aligment:'middle'});
		}
		return chartsjson;
	}
	function obtainLevel(level){
		switch(parseInt(level)){
			case 0: return {text:"critical", style:['text','critical']};
			case 1: return {text:"high", style:['text','high']};
			case 2: return {text:"middle", style:['text','middle']};
			case 3: return {text:"low", style:['text','low']};
			case 4: return {text:"informational", style:['text','informational']};
		}
	};

	function createVulnerabilitiesTable(){
		var vulns = $dataAccess.getTargetTechnical();
		var rows = [[ { text: 'ID', style:'th' }, { text: 'Target', style:'th' }, { text: 'Vulnerability', style:'th' }, { text: 'Criticality', style:'th' } ]];
		for(var i in vulns){
			var obj = [
				{text:vulns[i].nameIdentity, style:'text'},
				{text:vulns[i].resource, style:'text'},
				{text:vulns[i].display_name, style:'text'},
				obtainLevel(vulns[i].level)
			];
			rows.push(obj);
		}
		var table = {
			table:{
				headerRows:1,
				style:'miestilo',
			    widths: [ 'auto', '*', '*', "auto" ],
			    body:rows
			}	
		};
		return table;
	}

	function obtainTarget(id){
		return $dataAccess.getTargetById(id);	    		
	}
	function createTechnicalTable(){
		var dataTech = $dataAccess.getTargetTechnical();
		var result = [];
		for(var tech  in dataTech){
			var item = dataTech[tech];
			var table = {
				table:{
					headerRows:1,
				    widths: [ 'auto', '*', '*', "auto" ],
				    body:[
				    	[ { text: 'ID', style:"th" }, { text: 'Target', style:"th" }, { text: 'Vulnerability', style:"th" }, { text: 'Criticality',style:"th" } ],
				    	[{text:item.nameIdentity, style:'text'},{text:item.resource, style:'text'},{text:item.display_name, style:'text'},obtainLevel(item.level)]
				    ]
				}	
			};
			var taxonomy = [{ text: 'Taxonomy:', bold: true }];
			for(var i in item.taxonomy){
				taxonomy.push({text:item.taxonomy[i], style:'text'});
			}
			var references = [{ text: 'References:', bold: true }];
			for(var i in item.references){
				references.push({text:item.references[i], style: 'text'});
			}
			var tableDetail = {
				table:{
					headerRows:0,
					widths:['*'],
					body:[
						[{ text: 'Details', style: 'detail' }],
						[{ text: item.title, style: 'title' }],
						[
							//table de details
							{
								columns:[
									[{ text: 'Target:',style:"h3" },{text:item.resource, style:"text"}, { text: 'Vulnerability:', style:"h3" }, {text:item.display_name +" ("+item.data_subtype+")", style:"text"} , { text: 'Plugin ID:', style:"h3" },{text:item.plugin_id, style:"text"},{ text: 'Impact', style:"h3" },{text:item.impact+"", style:"text"}],
									[{ text: 'Criticality:', style:"h3" },obtainLevel(item.level), { text: 'Plugin name:', style:"h3" },{text:item.plugin_name, style:"text"},{ text: 'Severity:', style:"h3" },{text:item.severity+"", style:"text"}],
									[{ text: 'Risk:', style:"h3" },{text:item.risk+"", style:"text"}]
								]
							}
						],
						[
							{
								columns:[
									taxonomy
								]
							}
							
						],
						[
							{
								columns:[
									[{ text: 'Description:', style:"h3" }, {text:item.description, style:"text"}]
								]
							}
							
						],
						[
							{
								columns:[
									[{ text: 'Solution:', style:"h3" }, {text:item.solution, style:"text"}]
								]
							}
							
						],
						[
							{
								columns:[
									references
								]
							}
							
						],
					]
				}
			}
			result.push(table);
			result.push(tableDetail);
			result.push(" ");
		}
		return result;
	}

	service.createPdf = function(generalInfo,chartLevel, chartType, chartTarget){
		var dd = {			
			pageOrientation: generalInfo.orientation,	    
			content: [			    
				createHeader(generalInfo),
				' ',
			],

		  	styles: {
			    header: {
			      fontSize: 22,
			      bold: true,
			      margin:[0, 17, 0, 0]
			    },
			    headerPageLeft:{
			    	alignment:'left',
			    	margin:[10, 10, 10 , 10 ]
			    },
			    headerPageRight:{
			    	alignment:'right',
			    	margin:[10, 10, 10 , 10 ]
			    },
			    footerPage:{
			    	aligment:'right',
			    	margin:[10, 10, 10 , 10 ]
			    },
			    h2: {
			      fontSize: 18,
			      bold: true
			    },
			    detail: {
			      fontSize: 16,
			      bold: true
			    },
			    text:{
			    	fontSize:10
			    },
			    th:{
					fontSize:10,
					bold:true
			    },
			    h3:{
					fontSize: 12,
					bold:true
			    },
			    title:{
			    	fontSize: 14,
			      	bold: true
			    },
			    critical:{
			    	color:'#b40a9d'
			    },
			    high:{
			    	color:'#b00700'
			    },
			    middle:{
			    	color:'#d7ac00'
			    },
			    low:{
			    	color:'#019127'
			    },
			    informational:{
			    	color:'#0080ff'
			    }
			}
		};
		if(generalInfo.enabledHeader){
			dd.header = function(currentPage, pageCount) {
				var result = generalInfo.templateHeader.replace("%currentPage%", currentPage).replace("%totalPages%", pageCount);
				return { text: result, style:  'headerPageRight' };
			}
		}
		if(generalInfo.enabledFooter){
			dd.footer = function(currentPage, pageCount) {
				var result = generalInfo.templateFooter.replace("%currentPage%", currentPage).replace("%totalPages%", pageCount);
				return { text: result, style:  'footerPage' };
			}
		}
		if(generalInfo.summary.showSummary){
			dd.content.push(createSummary(generalInfo));
			dd.content.push(' ');
		}
		if(generalInfo.charts.showCharts){
			dd.content.push(createCharts(generalInfo, chartLevel, chartType, chartTarget ));
			dd.content.push(' ');
		}
		if(generalInfo.vulnerabilities.showVulnerabilities){
			dd.content.push({text:"Vulnerabilities", style:"h2"});
			dd.content.push(createVulnerabilitiesTable())
			dd.content.push(' ');
		}
		if(generalInfo.techReport.showTechnicalReport){
			dd.content.push({text:"Technical report", style:"h2"});
			var technicalTable = createTechnicalTable();
			for(var i in technicalTable){
				dd.content.push(technicalTable[i]);
			}
		}
		
		
		service.downloadPdf(generalInfo, dd);
	};

	return service;
}]);