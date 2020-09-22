using APIServer.Identity;
using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIServer.Supporting
{
    public class AutoMapperProfile: Profile
    {
        public AutoMapperProfile()
        {
           /*  CreateMap<AppUser, AccountResponse>();

            CreateMap<AppUser, AuthenticateResponse>();
           
                        CreateMap<RegisterRequest, Account>();

                        CreateMap<CreateRequest, Account>();

                        CreateMap<UpdateRequest, Account>()
                            .ForAllMembers(x => x.Condition(
                                (src, dest, prop) =>
                                {
                                    // ignore null & empty string properties
                                    if (prop == null) return false;
                                    if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                                    // ignore null role
                                    if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                                    return true;
                                }
                            ));*/
        }
    }
}
