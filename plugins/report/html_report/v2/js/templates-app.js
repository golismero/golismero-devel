angular.module('templates-app', ['confirm.tpl.html', 'custompdf.tpl.html', 'rowVulnTechnical.tpl.html', 'rowVulnerabilities.tpl.html']);

angular.module("confirm.tpl.html", []).run(["$templateCache", function($templateCache) {
  $templateCache.put("confirm.tpl.html",
    "<div class=\"modal-header\">\n" +
    "    <h3 class=\"modal-title\">Confirm delete vulnerability</h3>\n" +
    "</div>\n" +
    "<div class=\"modal-body\">\n" +
    "    <p>Are you sure you want to delete the vulnerability {{vulnerability.nameIdentity}}?</p>\n" +
    "</div>\n" +
    "<div class=\"modal-footer\">\n" +
    "    <button class=\"btn btn-default\" ng-click=\"accept()\">Yes</button>\n" +
    "    <button class=\"btn btn-primary\" ng-click=\"close()\">No</button>\n" +
    "</div>");
}]);

angular.module("custompdf.tpl.html", []).run(["$templateCache", function($templateCache) {
  $templateCache.put("custompdf.tpl.html",
    "<div class=\"modal-header\">\n" +
    "    <h3 class=\"modal-title\">Generate pdf</h3>\n" +
    "</div>\n" +
    "<div class=\"modal-body\">\n" +
    "	<tabset>\n" +
    "\n" +
    "		<tab heading=\"General\">\n" +
    "		    <div class=\"row\">\n" +
    "		    	<div class=\"col-sm-4\">\n" +
    "		    		<img class=\"img-logo\" ng-if=\"general.image\" ng-src=\"{{general.image}}\" alt=\"\">\n" +
    "					<input upload type=\"file\" name=\"upload\">\n" +
    "		    	</div>\n" +
    "		    	<div class=\"col-sm-8\">\n" +
    "		    		<form class=\"form-horizontal\" role=\"form\">\n" +
    "		    			<div class=\"form-group\">\n" +
    "							<label for=\"name-audit\" class=\"col-sm-3 control-label\">Audit name:</label>\n" +
    "							<div class=\"col-sm-9\">\n" +
    "								<input type=\"text\" class=\"form-control\" id=\"name-audit\" placeholder=\"Audit name\" ng-model=\"general.auditName\">\n" +
    "							</div>\n" +
    "						</div>\n" +
    "						<div class=\"form-group\">\n" +
    "							<label for=\"header\" class=\"col-sm-3 control-label\">Header:</label>\n" +
    "							<div class=\"col-sm-7\">\n" +
    "								<input type=\"text\" class=\"form-control\" id=\"footer\" placeholder=\"Header template\" ng-disabled=\"!general.enabledHeader\" ng-model=\"general.templateHeader\">						\n" +
    "							</div>\n" +
    "							<div class=\"col-sm-2\">\n" +
    "								<input type=\"checkbox\" class=\"\" id=\"header\" placeholder=\"Header template\" ng-model=\"general.enabledHeader\" >\n" +
    "							</div>\n" +
    "						</div>\n" +
    "						<div class=\"form-group\">\n" +
    "							<label for=\"name-audit\" class=\"col-sm-3 control-label\">Footer:</label>\n" +
    "							<div class=\"col-sm-7\">\n" +
    "								<input type=\"text\" class=\"form-control\" id=\"footer\" placeholder=\"Footer template\" ng-disabled=\"!general.enabledFooter\" ng-model=\"general.templateFooter\">						\n" +
    "							</div>\n" +
    "							<div class=\"col-sm-2\">\n" +
    "								<input type=\"checkbox\" class=\"\" id=\"footer\" placeholder=\"Footer template\" ng-model=\"general.enabledFooter\">\n" +
    "							</div>\n" +
    "						</div>\n" +
    "						<div class=\"form-group\">\n" +
    "							<label for=\"name-audit\" class=\"col-sm-3 control-label\">Orientation:</label>\n" +
    "							<div class=\"col-sm-9\">\n" +
    "								<input type=\"radio\" ng-model=\"general.orientation\" value=\"landscape\">Landscape</input>\n" +
    "								<input type=\"radio\" ng-model=\"general.orientation\" value=\"portrait\">Portrait</input>	\n" +
    "							</div>\n" +
    "							\n" +
    "						</div>\n" +
    "		    		</form>\n" +
    "		    	</div>\n" +
    "		    </div>\n" +
    "		    <hr>\n" +
    "		    <div class=\"row\">\n" +
    "		    	<div class=\"col-sm-3\">\n" +
    "		    		<h4>Summary block</h4>\n" +
    "		    		<div><input type=\"checkbox\" id=\"showSummary\" ng-model=\"general.summary.showSummary\">Show summary</input></div>\n" +
    "		    		<div class=\"submenu\"><input type=\"checkbox\" id=\"showTargets\" ng-model=\"general.summary.showTargets\" ng-disabled=\"!general.summary.showSummary\">Show targets</input></div>\n" +
    "					<div class=\"submenu\"><input type=\"checkbox\" id=\"showTimes\" ng-model=\"general.summary.showTimes\" ng-disabled=\"!general.summary.showSummary\">Show times</input></div>\n" +
    "					<div class=\"submenu\"><input type=\"checkbox\" id=\"showTotals\" ng-model=\"general.summary.showTotals\" ng-disabled=\"!general.summary.showSummary\">Show totals</input></div>			\n" +
    "		    	</div>\n" +
    "		    	<div class=\"col-sm-3\">\n" +
    "		    		<h4>Charts block</h4>\n" +
    "		    		<div><input type=\"checkbox\" id=\"showSummary\" ng-model=\"general.charts.showCharts\">Show charts</input></div>\n" +
    "		    		<div class=\"submenu\"><input type=\"checkbox\" id=\"showTargets\" ng-model=\"general.charts.showVulnCriticality\" ng-disabled=\"!general.charts.showCharts\">Show chart vulnerabilities by criticality</input></div>\n" +
    "					<div class=\"submenu\"><input type=\"checkbox\" id=\"showTimes\" ng-model=\"general.charts.showVulnsType\"  ng-disabled=\"!general.charts.showCharts\">Show chart vulnerabilities by type</input></div>\n" +
    "					<div class=\"submenu\"><input type=\"checkbox\" id=\"showTotals\" ng-model=\"general.charts.showVulnsTarget\" ng-disabled=\"!general.charts.showCharts\">Show chart vulnerabilities by target</input></div>		\n" +
    "		    	</div>\n" +
    "		    	<div class=\"col-sm-3\">\n" +
    "		    		<h4>Vulnerabilites block</h4>\n" +
    "		    		<div><input type=\"checkbox\" id=\"showSummary\" ng-model=\"general.vulnerabilities.showVulnerabilities\">Show vulnerabilities</input></div>    			\n" +
    "		    	</div>\n" +
    "		    	<div class=\"col-sm-3\">\n" +
    "		    		<h4>Technical report block</h4>\n" +
    "		    		<div><input type=\"checkbox\" id=\"showSummary\" ng-model=\"general.techReport.showTechnicalReport\">Show technical report</input></div>    			\n" +
    "		    	</div>\n" +
    "		    </div>\n" +
    "    	</tab>\n" +
    "    	<tab heading=\"Styles\">\n" +
    "    		Estilos\n" +
    "    	</tab>\n" +
    "    </tabset>\n" +
    "</div>\n" +
    "<div class=\"modal-footer\">\n" +
    "    <button class=\"btn btn-default\" ng-click=\"generate('open')\">Open (recomended firefox and chrome)</button>\n" +
    "    <button class=\"btn btn-default\" ng-click=\"generate('save')\">Save (recomended ie)</button>\n" +
    "    <button class=\"btn btn-primary\" ng-click=\"cancel()\">Cancel</button>\n" +
    "</div>");
}]);

angular.module("rowVulnTechnical.tpl.html", []).run(["$templateCache", function($templateCache) {
  $templateCache.put("rowVulnTechnical.tpl.html",
    "<tr data-anchor=\"technical-{{item.identity}}\" class=\"headData expanded\" ng-init=\"show=true\">\n" +
    "	<td  ng-click=\"show= !show\" class=\"tdRowTechCollapse\"><span class=\"glyphicon glyphicon-plus \" ng-show=\"show==false\"></span> <span class=\"glyphicon glyphicon-minus expanded\" ng-show=\"show == true\"></span></td>\n" +
    "	<td  class=\"tdRowTechIdentity\" ><span editable-text=\"item.nameIdentity\" buttons=\"no\">{{item.nameIdentity}}</span></td>\n" +
    "	<td  class=\"tdRowTechTarget\"><p class=\"large\">{{item.resource}}</p></td>\n" +
    "	<td  class=\"tdRowTechVuln hidden-xs\" ><span editable-text=\"item.display_name\" onaftersave=\"updateVulnerabilityType(item)\" buttons=\"no\">{{item.display_name}}</span></td>\n" +
    "	<td  class=\"tdRowTechLevel hidden-xs\" ><div editable-select=\"item.level\" e-ng-options=\"s.value as s.label for s in levels\" buttons=\"no\"  onaftersave=\"updateLevels(item)\"><span class=\"bold {{obtainLevel(item.level)}}Vulnerability\">{{obtainLevel(item.level)}}</span></div></td>\n" +
    "</tr>\n" +
    "<tr class=\"openVulnerabilitiesRow\" ng-show=\"show\"><td colspan=\"5\">\n" +
    "<div class=\"row \">\n" +
    "	<div class=\"col-sm-12\">\n" +
    "		<h4 editable-text=\"item.title\" buttons=\"no\">{{item.title}}</h4>\n" +
    "		<div class=\"well\">\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-12\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Target:</span>{{item.resource}}</div>\n" +
    "				</div>\n" +
    "			</div>\n" +
    "			<div class=\"row\">				\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Vulnerability:</span><span editable-text=\"item.display_name\" buttons=\"no\" onaftersave=\"updateVulnerabilityType(item)\">{{item.display_name}}</span>&nbsp;(<span editable-text=\"item.data_subtype\" buttons=\"no\">{{item.data_subtype}}</span>) </div>\n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold \">Criticality:</span><span class=\"{{obtainLevel(item.level)}}Vulnerability bold\" editable-select=\"item.level\" e-ng-options=\"s.value as s.label for s in levels\" buttons=\"no\"  onaftersave=\"updateLevels(item)\">{{obtainLevel(item.level)}}</span> </div>\n" +
    "				</div>\n" +
    "			</div>\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Plugin ID:</span><span editable-text=\"item.plugin_id\" buttons=\"no\">{{item.plugin_id}}</span></div> \n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Plugin name:</span><span editable-text=\"item.plugin_name\" buttons=\"no\">{{item.plugin_name}}</span></div>\n" +
    "				</div>	\n" +
    "				<div class=\"col-sm-4\">\n" +
    "				</div>			\n" +
    "			</div>\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Impact:</span><span editable-text=\"item.impact\" buttons=\"no\">{{item.impact}}</span> </div>\n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Severity:</span><span editable-text=\"item.severity\" buttons=\"no\">{{item.severity}}</span></div>\n" +
    "				</div>	\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Risk:</span><span editable-text=\"item.risk\" buttons=\"no\">{{item.risk}}</span></div>\n" +
    "				</div>			\n" +
    "			</div>\n" +
    "			\n" +
    "		</div>\n" +
    "		\n" +
    "		<div class=\"well\" ng-if=\"item.taxonomy\">\n" +
    "			<span class=\"bold\">Taxonomy:</span>\n" +
    "			<div ng-repeat=\"tax in item.taxonomy\">{{tax}}</div>\n" +
    "			\n" +
    "		</div>\n" +
    "		<div class=\"well\" ng-if=\"item.description\">\n" +
    "				<span class=\"bold\">Description:</span> <pre editable-textarea=\"item.description\" buttons=\"no\" e-rows=\"14\" e-cols=\"40\">{{item.description}}</pre>\n" +
    "			</div>\n" +
    "		<div class=\"well\" ng-if=\"item.solution\">\n" +
    "			<span class=\"bold\">Solution:</span> <pre editable-textarea=\"item.solution\" buttons=\"no\" e-rows=\"17\" e-cols=\"40\">{{item.solution}}</pre>\n" +
    "		</div>\n" +
    "		<div class=\"well\" ng-if=\"item.references\">	\n" +
    "			<span class=\"bold\">References:</span>\n" +
    "			<div ng-repeat=\"item in item.references\"><a href=\"{{item}}\" target=\"_blank\">{{item}}</a></div>\n" +
    "   		</div>\n" +
    "   	</div>\n" +
    "   </div>\n" +
    " </td></tr>\n" +
    "");
}]);

angular.module("rowVulnerabilities.tpl.html", []).run(["$templateCache", function($templateCache) {
  $templateCache.put("rowVulnerabilities.tpl.html",
    "<td editable-text=\"item.nameIdentity\" buttons=\"no\">{{item.nameIdentity}}</td>\n" +
    "<td><p class=\"large\" tooltip=\"{{item.resource}}\" tooltip-placement=\"bottom\">{{item.resource }}</p></td>		\n" +
    "<td ><span editable-text=\"item.display_name\" onaftersave=\"updateVulnerabilityType(item)\" buttons=\"no\"> {{item.display_name}}</span></td>\n" +
    "<td><span class=\"bold {{obtainLevel(item.level)}}Vulnerability\" editable-select=\"item.level\" buttons=\"no\" e-ng-options=\"s.value as s.label for s in levels\" onaftersave=\"updateLevels(item)\">{{obtainLevel(item.level)}}</span></td>\n" +
    "<td><span ng-click=\"deleteItem($index, item)\" class=\"glyphicon glyphicon-remove\"></span></td>\n" +
    "<td class=\"moreInfo\" ng-click=\"goTo(item.identity)\">Details</td>\n" +
    "");
}]);
