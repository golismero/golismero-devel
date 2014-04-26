angular.module('templates-app', ['rowVulnTechnical.tpl.html', 'rowVulnerabilities.tpl.html']);

angular.module("rowVulnTechnical.tpl.html", []).run(["$templateCache", function($templateCache) {
  $templateCache.put("rowVulnTechnical.tpl.html",
    "<tr data-anchor=\"technical-${identity}\" class=\"headData expanded\" ng-init=\"show=true\">\n" +
    "	<td style=\"width:30px\" ng-click=\"show= !show\"><span class=\"glyphicon glyphicon-plus \" ng-show=\"show==false\"></span> <span class=\"glyphicon glyphicon-minus expanded\" ng-show=\"show == true\"></td>\n" +
    "	<td style=\"width:245px\">{{item.identity}}</td>\n" +
    "	<td style=\"width:370px\"><p class=\"large\">{{obtainTarget(item.links)}}</p></td>\n" +
    "	<td style=\"\">{{item.display_name}}</td>\n" +
    "	<td style=\"width:80px\"><span class=\"bold {{obtainLevel(item.level)}}Vulnerability\">{{obtainLevel(item.level)}}</span></td>\n" +
    "</tr>\n" +
    "<tr class=\"openVulnerabilitiesRow\" ng-show=\"show\"><td colspan=\"5\">\n" +
    "<div class=\"row \">\n" +
    "	<div class=\"col-sm-12\">\n" +
    "		<h4>{{item.title}}</h4>\n" +
    "		<div class=\"well\">\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-12\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Target:</span>{{obtainTarget(item.links)}}</div>\n" +
    "				</div>\n" +
    "			</div>\n" +
    "			<div class=\"row\">				\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Vulnerability:</span>{{item.display_name}}&nbsp;({{item.data_subtype}}) </div>\n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold \">Criticality:</span><span class=\"´{{obtainLevel(item.level)}}Vulnerability bold\">{{obtainLevel(item.level)}}</span> </div>\n" +
    "				</div>\n" +
    "			</div>\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Plugin ID:</span>{{item.plugin_id}}</div> \n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Plugin name:</span>{{item.plugin_name}}</div>\n" +
    "				</div>	\n" +
    "				<div class=\"col-sm-4\">\n" +
    "				</div>			\n" +
    "			</div>\n" +
    "			<div class=\"row\">\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Impact:</span></span>{{item.impact}} </div>\n" +
    "				</div>\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Severity:</span>{{item.severity}}</div>\n" +
    "				</div>	\n" +
    "				<div class=\"col-sm-4\">\n" +
    "					<div class=\"item-form\"><span class=\"bold\">Risk:</span>{{item.risk}}</div>\n" +
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
    "				<span class=\"bold\">Description:</span> <pre>{{item.description}}</pre>\n" +
    "			</div>\n" +
    "		<div class=\"well\" ng-if=\"item.solution\">\n" +
    "			<span class=\"bold\">Solution:</span> <pre>{{item.solution}}</pre>\n" +
    "		</div>\n" +
    "		<div class=\"well\" ng-if=\"true\">	\n" +
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
    "<td>{{item.identity}}</td>\n" +
    "<td><p class=\"large\" tooltip  data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"{{item.resource}}\" data-original-title=\"{{item.resource}}\">{{item.resource }}</p></td>		\n" +
    "<td>{{item.display_name}}</td>\n" +
    "<td><span class=\"bold {{obtainLevel(item.level)}}Vulnerability\">{{obtainLevel(item.level)}}</span></td>\n" +
    "<td class=\"anchor moreInfo\" ng-click=\"goTo(item.identity)\">Details</td>\n" +
    "");
}]);
