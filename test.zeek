global re: table[addr] of set[string];
global ipu: set[addr];

event http_header(c:connection; is_orig:bool; name:string; value:string;)
	{
	if(c$id$orig_h in ipu)
		{
		}
	else
		{
		if(c$id$orig_h in re)
			{
				if(to_lower(c$http$user_agent) in re[c$id$orig_h])
					{
					}
				else
					{
					if(|re[c$id$orig_h]| ==2)
						{
						print fmt("%s is a proxy",c$id$orig_h);
						add ipu[c$id$orig_h];
						}
					else
						{
						add re[c$id$orig_h][to_lower(c$http$user_agent)];
						}
					}
			}
		else
			{
			local tem: set[string];
			add tem[to_lower(c$http$user_agent)];
			re[c$id$orig_h]=tem;
			}
		}
	
	}


