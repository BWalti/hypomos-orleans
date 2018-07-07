FROM microsoft/dotnet:2.1-sdk AS build

FROM build AS publish
WORKDIR /build
COPY . .
WORKDIR /build/src/Webapp
RUN dotnet publish -c Release -o /app

FROM microsoft/dotnet:2.1-sdk AS base
RUN apt-get -qq update && apt-get -qqy --no-install-recommends install wget gnupg git unzip
WORKDIR /app
EXPOSE 443 80

FROM base AS final
ENV ASPNETCORE_ENVIRONMENT Production
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "Webapp.dll"]
