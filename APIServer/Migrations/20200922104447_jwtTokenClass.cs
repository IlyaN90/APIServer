using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace APIServer.Migrations
{
    public partial class jwtTokenClass : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "JTokenId",
                table: "AspNetUsers",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "JwtTokens",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EmployeeId = table.Column<int>(nullable: false),
                    Token = table.Column<string>(nullable: true),
                    ExpirationDate = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JwtTokens", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_JTokenId",
                table: "AspNetUsers",
                column: "JTokenId");

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetUsers_JwtTokens_JTokenId",
                table: "AspNetUsers",
                column: "JTokenId",
                principalTable: "JwtTokens",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetUsers_JwtTokens_JTokenId",
                table: "AspNetUsers");

            migrationBuilder.DropTable(
                name: "JwtTokens");

            migrationBuilder.DropIndex(
                name: "IX_AspNetUsers_JTokenId",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "JTokenId",
                table: "AspNetUsers");
        }
    }
}
