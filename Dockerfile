FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
RUN apt-get update && apt-get install -y libgssapi-krb5-2 libkrb5-3 && rm -rf /var/lib/apt/lists/*

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN apt-get update && apt-get install -y libgssapi-krb5-2 libkrb5-3 && rm -rf /var/lib/apt/lists/*
RUN dotnet publish LicenseServer.csproj -c Release -o /app/out

FROM base AS final
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "LicenseServer.dll"]
