package academy.devdojo.youtube.course.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Service;

import academy.devdojo.youtube.core.model.Course;
import academy.devdojo.youtube.core.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@EntityScan({"academy.devdojo.youtube.core.model"})
@EnableJpaRepositories({"academy.devdojo.youtube.core.repository"})
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CourseService {

	private final CourseRepository courseRepository;
	
	public Iterable<Course> list(Pageable pageaable){
		log.info("listing all courses");
		return courseRepository.findAll(pageaable);
	}
}
