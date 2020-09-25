using Microsoft.EntityFrameworkCore.Migrations;

namespace APIServer.Migrations.Northwind
{
    public partial class jwttoken : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {

        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UserName",
                table: "Employees",
                type: "nvarchar(max)",
                nullable: true);
        }
    }
}
