FROM microsoft/dotnet:2.1-sdk AS publish
WORKDIR /build
COPY . .
WORKDIR /build/src/OrleansHost
RUN dotnet publish -c Release -o /app

FROM microsoft/aspnetcore:2.1 AS final
ENV ASPNETCORE_ENVIRONMENT Production
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "OrleansHost.dll"]
