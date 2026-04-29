package com.mxr.integration.service;

import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.mxr.integration.Response.AgifyResponse;
import com.mxr.integration.Response.GenderizeResponse;
import com.mxr.integration.Response.NationalizeResponse;
import com.mxr.integration.Response.PersonExistsResponse;
import com.mxr.integration.Response.ProcessedResponse;
import com.mxr.integration.exceptions.MissingGenderizeDataException;
import com.mxr.integration.exceptions.MissingOrEmptyNameException;
import com.mxr.integration.exceptions.PersonNotFoundException;
import com.mxr.integration.exceptions.AgifyExceptions.NullAgeException;
import com.mxr.integration.exceptions.NationalizeExceptions.MissingCountryDataException;
import com.mxr.integration.exceptions.InvalidNameException;
import com.mxr.integration.exceptions.InvalidQueryParametersException;
import com.mxr.integration.model.CountryData;
import com.mxr.integration.model.Person;
import com.mxr.integration.repo.PersonRepoImpl;
import com.mxr.integration.spec.PersonSpecification;

@Service
public class IntegrationService {

    private final PersonRepoImpl repo;

    IntegrationService(PersonRepoImpl personRepoImpl) {
        this.repo = personRepoImpl;
    }

    RestTemplate restTemplate = new RestTemplate();

    public ProcessedResponse savePerson(String name) {
        validateName(name);
        if (repo.existsByName(name)) {
            Person person = repo.findByNameIgnoreCase(name).get();
            return new PersonExistsResponse("success", person, "Profile already exists");
        }
        GenderizeResponse genderizeResponse = getGenderizeResponse(name);
        AgifyResponse agifyResponse = getAgifyResponse(name);
        NationalizeResponse nationalizeResponse = getNationalizeResponse(name);
        Person person = mapToPerson(genderizeResponse, agifyResponse, nationalizeResponse);
        repo.save(person);

        return new ProcessedResponse("success", person);
    }

    public Page<Person> searchPeople(String gender, String countryId, String ageGroup,
            Integer minimumAge, Integer maximumAge, Double minCountryProbability, Double minGenderProbability,
            Pageable pageable) {
        Specification<Person> spec = Specification
                .where(PersonSpecification.hasGender(gender))
                .and(PersonSpecification.hasCountryId(countryId))
                .and(PersonSpecification.hasAgeGroup(ageGroup))
                .and(PersonSpecification.greaterThanAge(minimumAge))
                .and(PersonSpecification.lessThanAge(maximumAge))
                .and(PersonSpecification.greaterThanCountryProbability(minCountryProbability))
                .and(PersonSpecification.greaterThanGenderProbability(minGenderProbability));

        return repo.findAll(spec, pageable);
    }

    public static String mapSortField(String sortBy) {
        if (sortBy == null)
            return "createdAt";
        return switch (sortBy.toLowerCase()) {
            case "age" -> "age";
            case "created_at" -> "createdAt";
            case "gender_probability" -> "genderProbability";
            default -> throw new InvalidQueryParametersException("Invalid sort field: " + sortBy);
        };
    }

    public Person getPersonById(UUID id) {
        return repo.findById(id).orElseThrow(() -> new PersonNotFoundException("Person not found"));
    }

    public void deletePerson(String name) {
        repo.deleteByName(name);
    }

    public void deletePersonById(UUID id) {
        if (!repo.existsById(id)) {
            throw new PersonNotFoundException("Person not found with id: " + id);
        }
        repo.deleteById(id);
    }

    public GenderizeResponse getGenderizeResponse(String name) {

        String genderizeUrl = "https://api.genderize.io/?name=" + name;
        GenderizeResponse genderizeResponse = restTemplate.getForObject(genderizeUrl, GenderizeResponse.class);

        if (genderizeResponse == null)
            throw new MissingGenderizeDataException("Genderize returned an invalid response");

        String gender = genderizeResponse.getGender();
        int count = genderizeResponse.getSampleSize();

        if (gender == null || count == 0)
            throw new MissingGenderizeDataException("Genderize returned an invalid response");
        return genderizeResponse;
    }

    public AgifyResponse getAgifyResponse(String name) {
        String agifyUrl = "https://api.agify.io?name=" + name;
        AgifyResponse agifyResponse = restTemplate.getForObject(agifyUrl, AgifyResponse.class);

        if (agifyResponse.getAge() == null)
            throw new NullAgeException("Agify returned an invalid response");

        return agifyResponse;
    }

    public NationalizeResponse getNationalizeResponse(String name) {
        String nationalizeUrl = "https://api.nationalize.io?name=" + name;
        NationalizeResponse nationalizeResponse = restTemplate.getForObject(nationalizeUrl, NationalizeResponse.class);
        List<CountryData> countries = nationalizeResponse.getCountries();
        if (countries == null || countries.isEmpty())
            throw new MissingCountryDataException("Nationalize returned an invalid response");

        return nationalizeResponse;
    }

    public Person mapToPerson(GenderizeResponse genderizeResponse, AgifyResponse agifyResponse,
            NationalizeResponse nationalizeResponse) {
        List<CountryData> countries = nationalizeResponse.getCountries();

        return Person.builder()
                .name(genderizeResponse.getName())
                .gender(genderizeResponse.getGender())
                .genderProbability(genderizeResponse.getProbability())
                .age(agifyResponse.getAge())
                .ageGroup(calculateAgeGroup(agifyResponse.getAge()))
                .countryId(getCountryWithHighestProbability(countries).getCountryId())
                .countryProbability(getCountryWithHighestProbability(countries).getProbability())
                .build();
    }

    private String calculateAgeGroup(int age) {
        if (age <= 12 && age >= 0)
            return "child";
        if (age <= 19 && age >= 13)
            return "teenager";
        if (age <= 59 && age >= 20)
            return "adult";
        if (age >= 60)
            return "senior";
        return "senior";
    }

    private CountryData getCountryWithHighestProbability(List<CountryData> countries) {
        return countries.stream()
                .max((c1, c2) -> Double.compare(c1.getProbability(), c2.getProbability()))
                .orElseThrow(() -> new MissingCountryDataException("No country data available for the provided name"));
    }

    private void validateName(String name) {
        if (name == null || name.isBlank())
            throw new MissingOrEmptyNameException("Name cannot be empty", name);
        if (name.matches(".*\\d.*"))
            throw new InvalidNameException("Name must contain only letters");
    }

}
