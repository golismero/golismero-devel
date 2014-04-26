angular.module('golismero-report-services', [])

.provider('dataAccess', [ function(){

	
	this.data = {};

	this.$get = function(){
		var data = this.data;
		var vulnerabilitiesArray = new Array();

		var targetsMap = new Array();
		var _self = this;
		var service = {};

		$.each(this.data.resources, function(key, val){		
			targetsMap[key] = val;
		});
		var targetMap = targetsMap;
		var vulnerabilitiesMap = new Array();

		service.getTargetById = function(id){
			if(id){
				var d = targetMap[id];
				if(d){
				    return d.display_content;
				}
			}
			return "";
		};

		service.getSummary = function(){
			return data.summary;
		}

		service.getDataVulnsByLevel= function(){
			return data.stats.vulns_by_level;
		}
		var vulnerabilitiesByTarget = [];
		$.each(this.data.vulnerabilities, function(key, val){		
			var o = new Object();
			o["resource"] = service.getTargetById(val.target_id);
			o["level"] = val.level;
			o["display_name"] = val.display_name;
			o["identity"] = val.identity;
			vulnerabilitiesMap.push(o);
			if(!vulnerabilitiesByTarget[o['resource']]){
				vulnerabilitiesByTarget[o['resource']] = 0;
			}
			vulnerabilitiesByTarget[o['resource']]+=1;
		});

		
		var auditScope = data.audit_scope;
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

		service.getVulnerabilitiesAngular = function() {
			return vulnerabilitiesMap;
		};
		service.getDataChartByTarget = function(){
			var dataChar = new Array();
			var _self = this;
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
		service.getVulnerabilitiesCountByTarget = function(target) {
			var bd = bbddVulnerabilitiesSimple();
			if(target){
				bd = bd.filter({'resource':{"left":target}});
			}			
			return bd.count();			
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
		return service;
	}
	this.setData = function(data) {
        this.data = data;
    };
}]);