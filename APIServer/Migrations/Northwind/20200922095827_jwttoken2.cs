using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace APIServer.Migrations.Northwind
{
    public partial class jwttoken2 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "JWTTokens",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EmployeeId = table.Column<int>(nullable: false),
                    Toke = table.Column<string>(nullable: true),
                    ValidTo = table.Column<DateTime>(nullable: false),
                    Revoked = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JWTTokens", x => x.Id);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "JWTTokens");
        }
    }
}
