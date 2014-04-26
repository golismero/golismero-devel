function initToTop(){
	    		$(".totop").hide();
				if($(this).scrollTop() > 80){
					//mostrar barra vertical lateral
					$("#lateralNavbar").show();
				}else{
					//ocultar barra
					$("#lateralNavbar").hide();
				}
				$(function(){
					$(window).scroll(function(){
						if($(this).scrollTop() > 80){
							//mostrar barra vertical lateral
							$("#lateralNavbar").show();
						}else{
							//ocultar barra
							$("#lateralNavbar").hide();
						}
						if ($(this).scrollTop()>600)
						{
							$('.totop').slideDown();
						}
						else
						{
							$('.totop').slideUp();
						}
						});

						$('.totop a').on("click touchstart", function (e) {
						e.preventDefault();
						$('body,html').animate({scrollTop: 0}, 500);
					});

				});
	    	}
	    
	    	function initLateralMenu(){
	    		$("#lateralNavbar").on("click touchstart", function(){
	    			if($(this).width() >20){
	    				//desplegada
	    				hideLateralMenu();
	    			}else{
	    				showLateralMenu();
	    			}
	    		});
	    		hideLateralMenu = function(){
	    			$( "#lateralNavbar" ).animate({
					    width: "20px"
					 }, {
					    duration: 500,
					   complete: function() {
					     $(this).removeClass("showLateralMenu");
					    }
					  });
	    		};
	    		showLateralMenu = function(){
	    			$( "#lateralNavbar" ).animate({
					    width: "50px"
					 }, {
					    duration: 500,
					   complete: function() {
					     $(this).addClass("showLateralMenu");
					    }
					  });
	    		}
	    		
	    	}
	    	
	    	$(document).ready(function(){
	    		initToTop();								
				initLateralMenu();
				//colocar mismo alto todos los quickInfo
				var maxHeigth=0;
				$(".quickInfo").each(function(){
					if($(this).outerHeight(false) > maxHeigth){
						maxHeigth= $(this).outerHeight(false);
					}
				});
				if(maxHeigth>220){
					maxHeigth = 220;
				}
				$(".quickInfo").each(function(){					
					$(this).css("height", maxHeigth+"px");
				});
			});