using Microsoft.EntityFrameworkCore.Migrations;

namespace APIServer.Migrations
{
    public partial class fkID : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetUsers_JwtTokens_EmployeeId",
                table: "AspNetUsers");

            migrationBuilder.DropForeignKey(
                name: "FK_AspNetUsers_RefreshTokens_EmployeeId",
                table: "AspNetUsers");

            migrationBuilder.DropIndex(
                name: "IX_AspNetUsers_EmployeeId",
                table: "AspNetUsers");

            migrationBuilder.AddColumn<string>(
                name: "appUserId",
                table: "RefreshTokens",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "appUserId",
                table: "JwtTokens",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_appUserId",
                table: "RefreshTokens",
                column: "appUserId",
                unique: true,
                filter: "[appUserId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_JwtTokens_appUserId",
                table: "JwtTokens",
                column: "appUserId",
                unique: true,
                filter: "[appUserId] IS NOT NULL");

            migrationBuilder.AddForeignKey(
                name: "FK_JwtTokens_AspNetUsers_appUserId",
                table: "JwtTokens",
                column: "appUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RefreshTokens_AspNetUsers_appUserId",
                table: "RefreshTokens",
                column: "appUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_JwtTokens_AspNetUsers_appUserId",
                table: "JwtTokens");

            migrationBuilder.DropForeignKey(
                name: "FK_RefreshTokens_AspNetUsers_appUserId",
                table: "RefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_appUserId",
                table: "RefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_JwtTokens_appUserId",
                table: "JwtTokens");

            migrationBuilder.DropColumn(
                name: "appUserId",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "appUserId",
                table: "JwtTokens");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_EmployeeId",
                table: "AspNetUsers",
                column: "EmployeeId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetUsers_JwtTokens_EmployeeId",
                table: "AspNetUsers",
                column: "EmployeeId",
                principalTable: "JwtTokens",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetUsers_RefreshTokens_EmployeeId",
                table: "AspNetUsers",
                column: "EmployeeId",
                principalTable: "RefreshTokens",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
